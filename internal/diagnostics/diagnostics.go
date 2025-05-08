package diagnostics

import (
	"fmt"

	"github.com/yourusername/my-monitor/internal/diagnostics/helpers"
)

func CheckService(url string) bool {
	fmt.Println("Проверка сервиса...")
	success, responseTime := helpers.CheckURL(url, 10)
	if success {
		fmt.Printf("Сервис доступен, время отклика: %.2f секунд\n", responseTime.Seconds())
		return true
	} else {
		fmt.Println("Сервис недоступен или не отвечает.")
		return false
	}
}

func PerformDiagnostics(host string) {
	fmt.Println("Запуск диагностики...")

	// DNS
	helpers.PrintDNS(host)

	// Ping
	helpers.Ping(host)

	// Traceroute
	helpers.Traceroute(host)

	// SSL сертификат
	helpers.CheckSSL(host)
}
