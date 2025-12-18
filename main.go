package main

import (
	"github.com/bakdauletbaktygaliyev/event-booking/db"
	"github.com/bakdauletbaktygaliyev/event-booking/routes"
	"github.com/gin-gonic/gin"
)

func main() {
	db.InitDB()
	server := gin.Default()
	routes.RegisterRoutes(server)

	server.Run(":8080") // localhost:8080
}
