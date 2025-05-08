package diagnostics

import (
	"fmt"

	"github.com/DeveloperDarkhan/servicehealth/internal/helpers"
)

var serviceStatus = true

func CheckService(url string) bool {
	fmt.Println("Проверка сервиса...")
	success, responseTime := helpers.CheckURL(url, 5)
	if success {
		fmt.Printf("Сервис доступен, время отклика: %.2f секунд\n", responseTime.Seconds())
		return true
	} else {
		fmt.Println("Сервис недоступен или не отвечает.")
		serviceStatus = false
		return false
	}
}

func PerformDiagnostics(host string) {
	fmt.Println("\nЗапуск диагностики...")

	// DNS
	helpers.PrintDNS(host)

	// Ping
	helpers.Ping(host)

	// Traceroute
	helpers.Traceroute(host)

	// SSL сертификат
	if serviceStatus {
		helpers.CheckSSL(host)
	}
}
