package main

import (
	"github.com/TechMDW/hashit/internal/cmd"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()

	cmd.Execute()
}
