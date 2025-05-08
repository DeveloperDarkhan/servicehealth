package helpers

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// Проверка URL с таймаутом
func CheckURL(url string, timeoutSeconds int) (bool, time.Duration) {
	client := &http.Client{
		Timeout: time.Duration(timeoutSeconds) * time.Second,
	}
	start := time.Now()
	resp, err := client.Get(url)
	duration := time.Since(start)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Printf("\nВремя ожидания истекло (таймаут: %d секунд)\n", timeoutSeconds)
		} else {
			fmt.Println("Ошибка при запросе:", err)
		}
		return false, duration
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, duration
}

// Проверка SSL сертификата
func CheckSSL(host string) {
	fmt.Println("\nПроверка SSL для:", host)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		fmt.Println("Ошибка подключения по TLS:", err)
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		fmt.Println("Выдан:", cert.Issuer)
		fmt.Println("Действителен до:", cert.NotAfter)
		remaining := cert.NotAfter.Sub(time.Now())
		fmt.Printf("До истечения срока: %v\n", remaining)
	} else {
		fmt.Println("Нет сертификатов")
	}
}

// Выполнение команды и вывод результата
func RunCommand(cmd string) {
	fmt.Println("Выполнение:", cmd)
	c := exec.Command("sh", "-c", cmd)
	output, err := c.CombinedOutput()
	if err != nil {
		fmt.Println("Ошибка выполнения:", err)
	}
	fmt.Println(string(output))
}

// DNS-запросы
func PrintDNS(host string) {
	// Убираем префиксы http:// и https://
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")

	fmt.Println("\nDNS-запрос для:", host)
	ips, err := net.LookupHost(host)
	if err != nil {
		fmt.Println("Ошибка при DNS-запросе:", err)
		return
	}

	fmt.Printf("IP адреса DNS-запроса: ")
	for i, ip := range ips {
		if i > 0 {
			fmt.Print(", ") // Добавляем запятую для разделения адресов
		}
		fmt.Print(ip)
	}
	fmt.Println() // добавляем перевод строки после вывода IP адресов

	// Дополнительно проверяем доступность портов
	for _, ip := range ips {
		CheckPorts(ip, []int{80, 443})
	}
}

// Проверка доступности портов с помощью netcat
func CheckPorts(ip string, ports []int) {

	fmt.Printf("\nПроверка доступности портов: %v\n", ports)
	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, 5*time.Second)

		if err != nil {
			fmt.Printf("Порт %d на %s недоступен: %v\n", port, ip, err)
		} else {
			fmt.Printf("Порт %d на %s доступен\n", port, ip)
			conn.Close()
		}
	}
}

func RunCommandPing(cmd string) (string, error) {
	outBytes, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(outBytes), err
}

// Ping хоста
func Ping(host string) {
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	fmt.Println("\nВыполнение: ping -c 4", host)

	output, err := RunCommandPing(fmt.Sprintf("ping -c 4 %s", host))

	// Не возвращаемся сразу, а анализируем вывод
	if err != nil {
		// Проверяем, является ли ошибка ExitError
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Получаем код выхода
			statusCode := exitErr.ExitCode()
			if statusCode == 2 {
				fmt.Println("ICMP закрыт для этого домена")
				return
			} else {
				fmt.Println("Ошибка выполнения, код:", statusCode)
				fmt.Println("Вывод:\n", output)
				return
			}
		} else {
			// Не связанная с кодом выхода ошибка
			fmt.Println("Ошибка выполнения:", err)
			return
		}
	}
}

// Traceroute до хоста
func Traceroute(host string) {
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	fmt.Println("\nTraceroute для:", host)
	// output, err := RunCommandPing(fmt.Sprintf("traceroute -m 10 %s", host))

	// // RunCommand(fmt.Sprintf("traceroute %s", host))
	// if err != nil {
	// 	fmt.Println("Ошибка выполнения:", err)
	// }
	// fmt.Println(string(output))

	// Создаём команду
	cmd := exec.Command("traceroute", "-m", "10", host)

	// Получаем поток stdout
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Ошибка получения stdoutPipe:", err)
		return
	}

	// Запускаем команду
	if err := cmd.Start(); err != nil {
		fmt.Println("Ошибка запуска команды:", err)
		return
	}

	// Создаём сканер для построчного чтения
	scanner := bufio.NewScanner(stdoutPipe)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line) // выводим каждую строку по мере получения
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Ошибка при чтении вывода:", err)
	}

	// Ждём завершения команды
	if err := cmd.Wait(); err != nil {
		fmt.Println("Ошибка выполнения команды:", err)
	}
}
