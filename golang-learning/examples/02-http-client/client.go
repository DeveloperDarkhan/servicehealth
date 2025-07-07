// Пример HTTP клиента
package main

import (
    "fmt"
    "io"
    "net/http"
    "time"
)

// Структура для конфигурации HTTP клиента
type HTTPClient struct {
    client  *http.Client
    timeout time.Duration
}

// Создание нового HTTP клиента
func NewHTTPClient(timeout time.Duration) *HTTPClient {
    return &HTTPClient{
        client: &http.Client{
            Timeout: timeout,
        },
        timeout: timeout,
    }
}

// Выполнение GET запроса
func (h *HTTPClient) Get(url string) (string, error) {
    fmt.Printf("Отправляем GET запрос на: %s\n", url)
    
    resp, err := h.client.Get(url)
    if err != nil {
        return "", fmt.Errorf("ошибка при выполнении запроса: %v", err)
    }
    defer resp.Body.Close()
    
    // Чтение тела ответа
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("ошибка при чтении ответа: %v", err)
    }
    
    fmt.Printf("Статус код: %d\n", resp.StatusCode)
    fmt.Printf("Размер ответа: %d байт\n", len(body))
    
    return string(body), nil
}

// Проверка доступности URL
func (h *HTTPClient) CheckHealth(url string) error {
    fmt.Printf("Проверяем доступность: %s\n", url)
    
    resp, err := h.client.Get(url)
    if err != nil {
        return fmt.Errorf("сервис недоступен: %v", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == 200 {
        fmt.Println("✅ Сервис работает нормально")
        return nil
    }
    
    return fmt.Errorf("❌ Сервис вернул код: %d", resp.StatusCode)
}

// Измерение времени ответа
func (h *HTTPClient) MeasureLatency(url string) (time.Duration, error) {
    start := time.Now()
    
    resp, err := h.client.Get(url)
    if err != nil {
        return 0, err
    }
    defer resp.Body.Close()
    
    latency := time.Since(start)
    fmt.Printf("Время ответа: %v\n", latency)
    
    return latency, nil
}

func main() {
    fmt.Println("=== HTTP клиент на Go ===")
    
    // Создаем HTTP клиент с таймаутом 10 секунд
    client := NewHTTPClient(10 * time.Second)
    
    // Список URL для тестирования
    urls := []string{
        "https://httpbin.org/status/200",
        "https://httpbin.org/delay/1",
        "https://google.com",
    }
    
    for i, url := range urls {
        fmt.Printf("\n--- Тест %d ---\n", i+1)
        
        // Проверка доступности
        err := client.CheckHealth(url)
        if err != nil {
            fmt.Printf("Ошибка: %v\n", err)
            continue
        }
        
        // Измерение времени ответа
        latency, err := client.MeasureLatency(url)
        if err != nil {
            fmt.Printf("Ошибка при измерении времени: %v\n", err)
            continue
        }
        
        if latency > 2*time.Second {
            fmt.Println("⚠️  Медленный ответ")
        } else {
            fmt.Println("⚡ Быстрый ответ")
        }
    }
    
    fmt.Println("\n=== Пример получения HTML ===")
    
    // Получение HTML страницы
    html, err := client.Get("https://httpbin.org/html")
    if err != nil {
        fmt.Printf("Ошибка: %v\n", err)
    } else {
        // Показываем первые 200 символов
        if len(html) > 200 {
            fmt.Printf("HTML (первые 200 символов):\n%s...\n", html[:200])
        } else {
            fmt.Printf("HTML:\n%s\n", html)
        }
    }
}