// Основная программа для проверки состояния сервисов
package main

import (
    "flag"
    "fmt"
    "go-healthcheck/pkg/checker"
    "go-healthcheck/pkg/logger"
    "os"
    "time"
)

func main() {
    // Определяем флаги командной строки
    var (
        url             = flag.String("url", "", "URL для проверки состояния (обязательный)")
        keyword         = flag.String("keyword", "Success", "Ключевое слово для поиска в ответе")
        timeout         = flag.Duration("timeout", 10*time.Second, "Таймаут HTTP запроса")
        logFile         = flag.String("log-file", "diagnostics.log", "Файл для логирования")
        fullDiagnostics = flag.Bool("full-diagnostics", false, "Включить полную диагностику")
        help            = flag.Bool("help", false, "Показать справку")
    )
    
    flag.Parse()
    
    // Показываем справку
    if *help {
        showHelp()
        return
    }
    
    // Проверяем обязательные параметры
    if *url == "" {
        fmt.Fprintf(os.Stderr, "Ошибка: параметр -url обязателен\n\n")
        showHelp()
        os.Exit(1)
    }
    
    // Создаем логгер
    log, err := logger.NewLogger(*logFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Ошибка создания логгера: %v\n", err)
        os.Exit(1)
    }
    defer log.Close()
    
    // Создаем конфигурацию
    config := &checker.Config{
        URL:             *url,
        Keyword:         *keyword,
        Timeout:         *timeout,
        FullDiagnostics: *fullDiagnostics,
        Logger:          log,
    }
    
    // Создаем проверщик состояния
    healthChecker := checker.NewHealthChecker(config)
    
    // Выполняем проверку
    fmt.Printf("Проверка состояния сервиса: %s\n", *url)
    fmt.Printf("Ключевое слово: %s\n", *keyword)
    fmt.Printf("Таймаут: %v\n", *timeout)
    
    if *fullDiagnostics {
        fmt.Println("Режим полной диагностики включен")
    }
    
    fmt.Println("Начинаем проверку...")
    fmt.Println()
    
    err = healthChecker.CheckHealth()
    if err != nil {
        fmt.Printf("FAILURE: %v\n", err)
        fmt.Printf("Подробности смотрите в файле лога: %s\n", *logFile)
        os.Exit(1)
    }
    
    fmt.Printf("Логи записаны в: %s\n", *logFile)
}

// showHelp показывает справку по использованию
func showHelp() {
    fmt.Println("Service Health Check - Проверка состояния веб-сервисов")
    fmt.Println()
    fmt.Println("Использование:")
    fmt.Println("  go run main.go -url <URL> [опции]")
    fmt.Println()
    fmt.Println("Обязательные параметры:")
    fmt.Println("  -url string")
    fmt.Println("      URL для проверки состояния")
    fmt.Println()
    fmt.Println("Опциональные параметры:")
    fmt.Println("  -keyword string")
    fmt.Println("      Ключевое слово для поиска в ответе (по умолчанию: 'Success')")
    fmt.Println("  -timeout duration")
    fmt.Println("      Таймаут HTTP запроса (по умолчанию: 10s)")
    fmt.Println("  -log-file string")
    fmt.Println("      Файл для логирования (по умолчанию: 'diagnostics.log')")
    fmt.Println("  -full-diagnostics")
    fmt.Println("      Включить полную диагностику")
    fmt.Println("  -help")
    fmt.Println("      Показать эту справку")
    fmt.Println()
    fmt.Println("Примеры:")
    fmt.Println("  go run main.go -url https://example.com/health")
    fmt.Println("  go run main.go -url https://example.com/health -keyword 'OK' -timeout 5s")
    fmt.Println("  go run main.go -url https://example.com/health -full-diagnostics")
    fmt.Println()
    fmt.Println("Функции:")
    fmt.Println("  ✓ Проверка HTTP статуса (200)")
    fmt.Println("  ✓ Поиск ключевого слова в ответе")
    fmt.Println("  ✓ Автоматическая диагностика при сбоях")
    fmt.Println("  ✓ Подробное логирование")
    fmt.Println()
    fmt.Println("Базовая диагностика:")
    fmt.Println("  - DNS разрешение")
    fmt.Println("  - Проверка порта 443")
    fmt.Println("  - SSL сертификат")
    fmt.Println("  - Измерение задержки")
    fmt.Println()
    fmt.Println("Полная диагностика (с флагом -full-diagnostics):")
    fmt.Println("  - Все проверки базовой диагностики")
    fmt.Println("  - Получение локального и публичного IP")
    fmt.Println("  - HTTP тайминги")
    fmt.Println("  - Анализ HTTP заголовков")
}