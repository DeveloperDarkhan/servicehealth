package main

import (
	"flag"
	"log"

	"github.com/DeveloperDarkhan/servicehealth/internal/diagnostics"
)

func main() {
	url := flag.String("url", "https://sre-test-assignment.innervate.tech/health.html", "URL сервиса для проверки")
	diagnosticsFlag := flag.Bool("diagnostics", false, "Запустить диагностику при неуспехе")
	verbose := flag.Bool("verbose", false, "Включить подробный вывод")
	flag.Parse()

	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	success := diagnostics.CheckService(*url)
	if !success && *diagnosticsFlag {
		diagnostics.PerformDiagnostics(*url)
	}
}
