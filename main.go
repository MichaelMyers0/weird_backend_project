package main
import(
        "log"
        "github.com/joho/godotenv"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"github.com/golang-jwt/jwt/v4"
	"time"
)
type User struct
{
	gorm.Model
	Email string `gorm:"unique"`
	Password string
}
var DB *gorm.DB

func LoadEnvVariables(){
        err := godotenv.Load()
        if err != nil{
                log.Fatal("Error loading .env file")
        }
}
func ConnectToDb(){
	var err error
	dsn := os.Getenv("DB")
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to DB")
	}
}
func SyncDatabase(){
        DB.AutoMigrate(&User{})
}
func Signup(c *gin.Context){
	//Get the email/pass off req body
	var body struct {
		Email string
		Password string

	}
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":"Failed to read body",})
		return	
	}
	//Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
                        "error":"Failed to hash password",})
                return
	}
	// Create the user
	user := User{Email:body.Email, Password:string(hash)}
	result := DB.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
                        "error":"Failed to read body",})
                return
	}
	// Respond
	c.JSON(http.StatusOK, gin.H{})
}
func Login(c *gin.Context){
	//Get the email and passwd of req body
	var body struct {
            Email string
            Password string
        }
        if c.Bind(&body) != nil {
                c.JSON(http.StatusBadRequest, gin.H{
                        "error":"Failed to read body",})
                return
        }
	//Look up requested user
	var user User
	DB.First(&user, "email = ?", body.Email)
	if user.ID == 0 {
		 c.JSON(http.StatusBadRequest, gin.H{
                        "error":"Invalid email or password",})
                return
	}
	//compare sent in pass with saved user pass hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		 c.JSON(http.StatusBadRequest, gin.H{
                        "error":"Failed to read body",})
                return
	}
	//Generate a jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.ID,
		"exp":time.Now().Add(time.Hour * 24 * 30).Unix(),
	})
	//Sign and get the compelete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		 c.JSON(http.StatusBadRequest, gin.H{
                        "error":"Failed to creat token",})
                return
	}
	//send it back
	c.JSON(http.StatusOK, gin.H{
		"token" : tokenString,
	})
}
func Validate(c *gin.Context){
	user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{
		"message":user,
	})
}
//middleware
func RequireAuth(c *gin.Context){
	tokenString, err := c.Cookie("Authorization")
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	return []byte(os.Getenv("SECRET")), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))
	if err != nil {
		log.Fatal(err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if float64(time.Now().Unix()) > claims["expr"].(float64){
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		var user User
		DB.First(&user, claims["sub"])
		if user.ID == 0 {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		c.Set("user", user)
		c.Next()
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}
func init(){
	LoadEnvVariables()
	ConnectToDb()
	SyncDatabase()
}
func main(){
	r := gin.Default()
	r.POST("/singup", Signup)
	r.POST("login", Login)
	r.GET("/validate", RequireAuth, Validate)
	r.Run()
}
