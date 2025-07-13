FROM ubuntu:latest
RUN apt update
RUN apt install golang-go apt install golang-go 
RUN go mod init 
RUN go get -u gorm.io/gorm
RUN go get -u gorm.io/driver/postgres 
RUN go get -u github.com/gin-gonic/gin 
RUN go get -u golang.org/x/crypto/bcrypt 
RUN go get -u github.com/golang-jwt/jwt/v4 
RUN go get github.com/joho/godotenv
COPY . /weird_backend_project
RUN go build
CMD ["./weird_backend_project"]
