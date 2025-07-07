// Package checker предоставляет функции для проверки состояния сервисов
package checker

import (
    "crypto/tls"
    "fmt"
    "go-healthcheck/pkg/logger"
    "io"
    "net"
    "net/http"
    "net/url"
    "strings"
    "time"
)

// Config содержит настройки для проверки
type Config struct {
    URL             string
    Keyword         string
    Timeout         time.Duration
    FullDiagnostics bool
    Logger          *logger.Logger
}

// HealthChecker выполняет проверки состояния сервисов
type HealthChecker struct {
    config *Config
    client *http.Client
}

// NewHealthChecker создает новый экземпляр проверки состояния
func NewHealthChecker(config *Config) *HealthChecker {
    return &HealthChecker{
        config: config,
        client: &http.Client{
            Timeout: config.Timeout,
        },
    }
}

// CheckHealth выполняет основную проверку состояния
func (hc *HealthChecker) CheckHealth() error {
    // Проверяем URL
    parsedURL, err := url.Parse(hc.config.URL)
    if err != nil {
        return fmt.Errorf("некорректный URL: %v", err)
    }
    
    // Выполняем HTTP запрос
    resp, err := hc.client.Get(hc.config.URL)
    if err != nil {
        hc.config.Logger.ErrorF("HTTP_CHECK", "Не удалось выполнить запрос: %v", err)
        
        // Запускаем диагностику
        if hc.config.FullDiagnostics {
            hc.config.Logger.Info("CONFIG", "Режим полной диагностики включен")
            hc.runFullDiagnostics(parsedURL.Hostname())
        } else {
            hc.runBasicDiagnostics(parsedURL.Hostname())
        }
        
        return err
    }
    defer resp.Body.Close()
    
    // Проверяем статус код
    if resp.StatusCode != 200 {
        hc.config.Logger.ErrorF("HTTP_CHECK", "Получен код состояния %d", resp.StatusCode)
        
        // Запускаем диагностику
        if hc.config.FullDiagnostics {
            hc.config.Logger.Info("CONFIG", "Режим полной диагностики включен")
            hc.runFullDiagnostics(parsedURL.Hostname())
        } else {
            hc.runBasicDiagnostics(parsedURL.Hostname())
        }
        
        return fmt.Errorf("получен код состояния %d", resp.StatusCode)
    }
    
    // Читаем тело ответа
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        hc.config.Logger.ErrorF("HTTP_CHECK", "Не удалось прочитать тело ответа: %v", err)
        return fmt.Errorf("не удалось прочитать тело ответа: %v", err)
    }
    
    // Проверяем наличие ключевого слова
    bodyStr := string(body)
    if !strings.Contains(bodyStr, hc.config.Keyword) {
        hc.config.Logger.ErrorF("HTTP_CHECK", "Ключевое слово \"%s\" не найдено в теле ответа", hc.config.Keyword)
        
        // Запускаем диагностику
        if hc.config.FullDiagnostics {
            hc.config.Logger.Info("CONFIG", "Режим полной диагностики включен")
            hc.runFullDiagnostics(parsedURL.Hostname())
        } else {
            hc.runBasicDiagnostics(parsedURL.Hostname())
        }
        
        return fmt.Errorf("ключевое слово \"%s\" не найдено", hc.config.Keyword)
    }
    
    // Все проверки пройдены успешно
    hc.config.Logger.InfoF("HTTP_CHECK", "Код состояния %d и тело ответа содержит ключевое слово \"%s\"", 
        resp.StatusCode, hc.config.Keyword)
    
    fmt.Printf("SUCCESS: Сервис работает корректно\n")
    return nil
}

// runBasicDiagnostics выполняет базовую диагностику
func (hc *HealthChecker) runBasicDiagnostics(hostname string) {
    // DNS проверка
    hc.checkDNS(hostname)
    
    // Проверка порта 443
    hc.checkPort(hostname, 443)
    
    // SSL проверка
    hc.checkSSL(hostname)
    
    // Измерение задержки
    hc.measureLatency(hostname)
}

// runFullDiagnostics выполняет полную диагностику
func (hc *HealthChecker) runFullDiagnostics(hostname string) {
    // Сначала базовая диагностика
    hc.runBasicDiagnostics(hostname)
    
    // Дополнительные проверки
    hc.getLocalIP()
    hc.getPublicIP()
    hc.checkHTTPTiming()
    hc.checkHTTPHeaders()
}

// checkDNS проверяет DNS разрешение
func (hc *HealthChecker) checkDNS(hostname string) {
    ips, err := net.LookupIP(hostname)
    if err != nil {
        hc.config.Logger.ErrorF("DNS_CHECK", "Не удалось разрешить DNS для %s: %v", hostname, err)
        return
    }
    
    var ipStrings []string
    for _, ip := range ips {
        ipStrings = append(ipStrings, ip.String())
    }
    
    hc.config.Logger.InfoF("DNS_CHECK", "DNS разрешение для %s: %s", hostname, strings.Join(ipStrings, ", "))
}

// checkPort проверяет доступность порта
func (hc *HealthChecker) checkPort(hostname string, port int) {
    address := fmt.Sprintf("%s:%d", hostname, port)
    conn, err := net.DialTimeout("tcp", address, 5*time.Second)
    if err != nil {
        hc.config.Logger.ErrorF("PORT_CHECK", "Порт %d недоступен для %s: %v", port, hostname, err)
        return
    }
    defer conn.Close()
    
    hc.config.Logger.InfoF("PORT_CHECK", "Порт %d доступен для %s", port, hostname)
}

// checkSSL проверяет SSL сертификат
func (hc *HealthChecker) checkSSL(hostname string) {
    conn, err := tls.Dial("tcp", hostname+":443", &tls.Config{
        ServerName: hostname,
    })
    if err != nil {
        hc.config.Logger.ErrorF("SSL_CHECK", "Не удалось установить SSL соединение с %s: %v", hostname, err)
        return
    }
    defer conn.Close()
    
    certs := conn.ConnectionState().PeerCertificates
    if len(certs) == 0 {
        hc.config.Logger.Error("SSL_CHECK", "SSL сертификат не найден")
        return
    }
    
    cert := certs[0]
    now := time.Now()
    
    if now.After(cert.NotAfter) {
        hc.config.Logger.ErrorF("SSL_CHECK", "SSL сертификат истек %s", cert.NotAfter.Format("2006-01-02"))
        return
    }
    
    daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
    if daysUntilExpiry < 30 {
        hc.config.Logger.WarningF("SSL_CHECK", "SSL сертификат истекает через %d дней", daysUntilExpiry)
    } else {
        hc.config.Logger.InfoF("SSL_CHECK", "SSL сертификат действителен (истекает через %d дней)", daysUntilExpiry)
    }
}

// measureLatency измеряет задержку
func (hc *HealthChecker) measureLatency(hostname string) {
    start := time.Now()
    
    conn, err := net.DialTimeout("tcp", hostname+":443", 5*time.Second)
    if err != nil {
        hc.config.Logger.ErrorF("LATENCY_CHECK", "Не удалось измерить задержку для %s: %v", hostname, err)
        return
    }
    defer conn.Close()
    
    latency := time.Since(start)
    hc.config.Logger.InfoF("LATENCY_CHECK", "Задержка до %s: %v", hostname, latency)
}

// getLocalIP получает локальный IP адрес
func (hc *HealthChecker) getLocalIP() {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        hc.config.Logger.ErrorF("LOCAL_IP", "Не удалось получить локальный IP: %v", err)
        return
    }
    defer conn.Close()
    
    localAddr := conn.LocalAddr().(*net.UDPAddr)
    hc.config.Logger.InfoF("LOCAL_IP", "Локальный IP адрес: %s", localAddr.IP)
}

// getPublicIP получает публичный IP адрес
func (hc *HealthChecker) getPublicIP() {
    client := &http.Client{Timeout: 5 * time.Second}
    resp, err := client.Get("https://api.ipify.org")
    if err != nil {
        hc.config.Logger.ErrorF("PUBLIC_IP", "Не удалось получить публичный IP: %v", err)
        return
    }
    defer resp.Body.Close()
    
    ip, err := io.ReadAll(resp.Body)
    if err != nil {
        hc.config.Logger.ErrorF("PUBLIC_IP", "Не удалось прочитать публичный IP: %v", err)
        return
    }
    
    hc.config.Logger.InfoF("PUBLIC_IP", "Публичный IP адрес: %s", string(ip))
}

// checkHTTPTiming проверяет тайминги HTTP
func (hc *HealthChecker) checkHTTPTiming() {
    start := time.Now()
    
    resp, err := hc.client.Get(hc.config.URL)
    if err != nil {
        hc.config.Logger.ErrorF("HTTP_TIMING", "Не удалось выполнить запрос для измерения тайминга: %v", err)
        return
    }
    defer resp.Body.Close()
    
    // Читаем тело ответа
    _, err = io.ReadAll(resp.Body)
    if err != nil {
        hc.config.Logger.ErrorF("HTTP_TIMING", "Не удалось прочитать тело ответа: %v", err)
        return
    }
    
    totalTime := time.Since(start)
    hc.config.Logger.InfoF("HTTP_TIMING", "Общее время HTTP запроса: %v", totalTime)
}

// checkHTTPHeaders проверяет HTTP заголовки
func (hc *HealthChecker) checkHTTPHeaders() {
    resp, err := hc.client.Get(hc.config.URL)
    if err != nil {
        hc.config.Logger.ErrorF("HTTP_HEADERS", "Не удалось получить заголовки: %v", err)
        return
    }
    defer resp.Body.Close()
    
    // Проверяем важные заголовки безопасности
    securityHeaders := []string{
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
    }
    
    for _, header := range securityHeaders {
        if value := resp.Header.Get(header); value != "" {
            hc.config.Logger.InfoF("HTTP_HEADERS", "Заголовок безопасности %s: %s", header, value)
        } else {
            hc.config.Logger.WarningF("HTTP_HEADERS", "Заголовок безопасности %s отсутствует", header)
        }
    }
    
    // Проверяем server header
    if server := resp.Header.Get("Server"); server != "" {
        hc.config.Logger.InfoF("HTTP_HEADERS", "Server: %s", server)
    }
}