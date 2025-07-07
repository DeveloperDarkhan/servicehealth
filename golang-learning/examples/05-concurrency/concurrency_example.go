// Пример параллельности (concurrency) в Go
package main

import (
    "fmt"
    "math/rand"
    "sync"
    "time"
)

// Структура для задачи
type Task struct {
    ID   int
    Name string
    Duration time.Duration
}

// Структура для результата
type Result struct {
    TaskID int
    Success bool
    Message string
    Duration time.Duration
}

func main() {
    fmt.Println("=== Параллельность в Go ===")
    
    // 1. Простые горутины
    fmt.Println("\n1. Простые горутины")
    
    // Запускаем несколько горутин
    for i := 1; i <= 5; i++ {
        go simpleWorker(i)
    }
    
    // Ждем немного, чтобы горутины выполнились
    time.Sleep(2 * time.Second)
    
    // 2. Горутины с каналами
    fmt.Println("\n2. Горутины с каналами")
    
    // Создаем канал для передачи сообщений
    messages := make(chan string, 5)
    
    // Запускаем горутины, которые отправляют сообщения
    for i := 1; i <= 3; i++ {
        go messageWorker(i, messages)
    }
    
    // Читаем сообщения из канала
    for i := 0; i < 3; i++ {
        msg := <-messages
        fmt.Printf("Получено сообщение: %s\n", msg)
    }
    
    // 3. Worker pool pattern
    fmt.Println("\n3. Worker pool pattern")
    
    // Создаем каналы для задач и результатов
    tasks := make(chan Task, 10)
    results := make(chan Result, 10)
    
    // Создаем задачи
    taskList := []Task{
        {ID: 1, Name: "Обработка файла", Duration: 1 * time.Second},
        {ID: 2, Name: "Отправка email", Duration: 2 * time.Second},
        {ID: 3, Name: "Резервное копирование", Duration: 3 * time.Second},
        {ID: 4, Name: "Аналитика", Duration: 1 * time.Second},
        {ID: 5, Name: "Уведомления", Duration: 2 * time.Second},
    }
    
    // Запускаем воркеров
    const numWorkers = 3
    var wg sync.WaitGroup
    
    for i := 1; i <= numWorkers; i++ {
        wg.Add(1)
        go worker(i, tasks, results, &wg)
    }
    
    // Отправляем задачи
    go func() {
        for _, task := range taskList {
            tasks <- task
        }
        close(tasks)
    }()
    
    // Собираем результаты
    go func() {
        wg.Wait()
        close(results)
    }()
    
    // Читаем результаты
    fmt.Println("Результаты выполнения задач:")
    for result := range results {
        status := "✅ Успешно"
        if !result.Success {
            status = "❌ Ошибка"
        }
        fmt.Printf("Задача %d: %s (выполнена за %v)\n", 
            result.TaskID, status, result.Duration)
    }
    
    // 4. Таймеры и таймауты
    fmt.Println("\n4. Таймеры и таймауты")
    
    // Канал для результата с таймаутом
    resultChan := make(chan string, 1)
    
    // Горутина с долгой работой
    go func() {
        time.Sleep(3 * time.Second)
        resultChan <- "Долгая операция завершена"
    }()
    
    // Ждем результат с таймаутом
    select {
    case result := <-resultChan:
        fmt.Printf("Результат: %s\n", result)
    case <-time.After(2 * time.Second):
        fmt.Println("Таймаут! Операция заняла слишком много времени")
    }
    
    // 5. Ticker для периодических задач
    fmt.Println("\n5. Периодические задачи")
    
    // Создаем ticker, который срабатывает каждые 500ms
    ticker := time.NewTicker(500 * time.Millisecond)
    done := make(chan bool)
    
    go func() {
        count := 0
        for {
            select {
            case <-done:
                return
            case t := <-ticker.C:
                count++
                fmt.Printf("Tick %d в %v\n", count, t.Format("15:04:05"))
                if count >= 5 {
                    done <- true
                }
            }
        }
    }()
    
    // Ждем завершения
    <-done
    ticker.Stop()
    
    // 6. Состояние гонки (race condition) и мьютексы
    fmt.Println("\n6. Мьютексы и состояние гонки")
    
    // Без мьютекса (небезопасно)
    fmt.Println("Небезопасный счетчик:")
    unsafeCounterExample()
    
    // С мьютексом (безопасно)
    fmt.Println("Безопасный счетчик:")
    safeCounterExample()
    
    fmt.Println("\n=== Завершение примера параллельности ===")
}

// Простая горутина
func simpleWorker(id int) {
    for i := 0; i < 3; i++ {
        fmt.Printf("Воркер %d выполняет задачу %d\n", id, i+1)
        time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
    }
}

// Горутина с каналом
func messageWorker(id int, messages chan<- string) {
    time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
    messages <- fmt.Sprintf("Сообщение от воркера %d", id)
}

// Воркер для обработки задач
func worker(id int, tasks <-chan Task, results chan<- Result, wg *sync.WaitGroup) {
    defer wg.Done()
    
    for task := range tasks {
        fmt.Printf("Воркер %d начал выполнение задачи %d: %s\n", 
            id, task.ID, task.Name)
        
        start := time.Now()
        
        // Симуляция работы
        time.Sleep(task.Duration)
        
        duration := time.Since(start)
        
        // Случайная ошибка для демонстрации
        success := rand.Float32() > 0.2
        
        result := Result{
            TaskID:   task.ID,
            Success:  success,
            Duration: duration,
        }
        
        if success {
            result.Message = "Задача выполнена успешно"
        } else {
            result.Message = "Ошибка выполнения задачи"
        }
        
        results <- result
        
        fmt.Printf("Воркер %d завершил задачу %d\n", id, task.ID)
    }
}

// Небезопасный счетчик
func unsafeCounterExample() {
    var counter int
    var wg sync.WaitGroup
    
    // Запускаем 10 горутин, каждая увеличивает счетчик 1000 раз
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for j := 0; j < 1000; j++ {
                counter++
            }
        }()
    }
    
    wg.Wait()
    fmt.Printf("Небезопасный счетчик: %d (должно быть 10000)\n", counter)
}

// Безопасный счетчик с мьютексом
func safeCounterExample() {
    var counter int
    var mutex sync.Mutex
    var wg sync.WaitGroup
    
    // Запускаем 10 горутин, каждая увеличивает счетчик 1000 раз
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for j := 0; j < 1000; j++ {
                mutex.Lock()
                counter++
                mutex.Unlock()
            }
        }()
    }
    
    wg.Wait()
    fmt.Printf("Безопасный счетчик: %d (должно быть 10000)\n", counter)
}