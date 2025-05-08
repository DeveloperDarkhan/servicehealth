package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"time"
)

func main() {
	// Аргумент --url для указания URL сервиса
	url := flag.String("url", "https://sre-test-assignment.innervate.tech/health.html", "URL сервиса для проверки")
	flag.Parse()

	fmt.Printf("Проверка сервиса по URL: %s\n", *url)

	// Создаем клиент с таймаутом 5 секунд
	timeout := 5 * time.Second

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get(*url)
	duration := time.Since(start)

	if err != nil {
		// Проверка на таймаут
		if err, ok := err.(net.Error); ok && err.Timeout() {
			fmt.Printf("Время ожидания истекло (таймаут: %v секунд).\n", timeout.Seconds())
		} else {
			fmt.Println("Ошибка при запросе:", err)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Println("Сервис доступен, статус 200.")
		fmt.Printf("Время отклика: %.2f секунд\n", duration.Seconds())
	} else {
		fmt.Println("Получен неожиданный статус:", resp.Status)
	}
}
