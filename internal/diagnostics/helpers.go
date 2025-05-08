package helpers

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"time"
)

// Проверка URL с таймаутом
func CheckURL(url string, timeoutSeconds int) (bool, time.Duration) {
	client := &http.Client{
		Timeout: time.Duration(timeoutSeconds) * time.Second,
	}
	start := time.now()
	resp, err := client.Get(url)
	duration := time.Since(start)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Printf("Время ожидания истекло (таймаут: %d секунд)\n", timeoutSeconds)
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
	fmt.Println("Проверка SSL для:", host)
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
	fmt.Println("DNS-запрос для:", host)
	ips, err := net.LookupHost(host)
	if err != nil {
		fmt.Println("Ошибка при DNS-запросе:", err)
		return
	}
	for _, ip := range ips {
		fmt.Println(ip)
	}

	// Дополнительно проверяем доступность портов
	for _, ip := range ips {
		CheckPorts(ip, []int{80, 443})
	}
}

// Проверка доступности портов с помощью netcat
func CheckPorts(ip string, ports []int) {
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

// Ping хоста
func Ping(host string) {
	fmt.Println("Ping для:", host)
	RunCommand(fmt.Sprintf("ping -c 4 %s", host))
}

// Traceroute до хоста
func Traceroute(host string) {
	fmt.Println("Traceroute для:", host)
	RunCommand(fmt.Sprintf("traceroute %s", host))
}
