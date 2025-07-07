// Пример работы с JSON
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

// Структура для пользователя
type User struct {
    ID       int    `json:"id"`
    Name     string `json:"name"`
    Username string `json:"username"`
    Email    string `json:"email"`
    Phone    string `json:"phone"`
    Website  string `json:"website"`
    Company  struct {
        Name        string `json:"name"`
        CatchPhrase string `json:"catchPhrase"`
        BS          string `json:"bs"`
    } `json:"company"`
}

// Структура для поста
type Post struct {
    UserID int    `json:"userId"`
    ID     int    `json:"id"`
    Title  string `json:"title"`
    Body   string `json:"body"`
}

// Структура для конфигурации
type Config struct {
    ServerURL string        `json:"server_url"`
    Timeout   time.Duration `json:"timeout"`
    Debug     bool          `json:"debug"`
    MaxRetries int          `json:"max_retries"`
}

func main() {
    fmt.Println("=== Работа с JSON в Go ===")
    
    // 1. Создание JSON из структуры
    fmt.Println("\n1. Создание JSON из структуры")
    config := Config{
        ServerURL:  "https://api.example.com",
        Timeout:    30 * time.Second,
        Debug:      true,
        MaxRetries: 3,
    }
    
    configJSON, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        fmt.Printf("Ошибка создания JSON: %v\n", err)
        return
    }
    
    fmt.Printf("Конфигурация в JSON:\n%s\n", string(configJSON))
    
    // 2. Парсинг JSON в структуру
    fmt.Println("\n2. Парсинг JSON в структуру")
    jsonData := `{
        "server_url": "https://api.prod.com",
        "timeout": 60000000000,
        "debug": false,
        "max_retries": 5
    }`
    
    var newConfig Config
    err = json.Unmarshal([]byte(jsonData), &newConfig)
    if err != nil {
        fmt.Printf("Ошибка парсинга JSON: %v\n", err)
        return
    }
    
    fmt.Printf("Распарсенная конфигурация:\n")
    fmt.Printf("URL: %s\n", newConfig.ServerURL)
    fmt.Printf("Таймаут: %v\n", newConfig.Timeout)
    fmt.Printf("Отладка: %t\n", newConfig.Debug)
    fmt.Printf("Повторы: %d\n", newConfig.MaxRetries)
    
    // 3. Получение данных из API
    fmt.Println("\n3. Получение данных из API")
    
    // Получаем пользователей
    users, err := fetchUsers()
    if err != nil {
        fmt.Printf("Ошибка получения пользователей: %v\n", err)
        return
    }
    
    fmt.Printf("Получено %d пользователей:\n", len(users))
    for i, user := range users {
        if i >= 3 { // Показываем только первых 3
            fmt.Printf("... и еще %d пользователей\n", len(users)-3)
            break
        }
        fmt.Printf("- %s (%s) - %s\n", user.Name, user.Username, user.Email)
    }
    
    // Получаем посты
    posts, err := fetchPosts()
    if err != nil {
        fmt.Printf("Ошибка получения постов: %v\n", err)
        return
    }
    
    fmt.Printf("\nПолучено %d постов:\n", len(posts))
    for i, post := range posts {
        if i >= 3 { // Показываем только первые 3
            fmt.Printf("... и еще %d постов\n", len(posts)-3)
            break
        }
        fmt.Printf("- Post %d: %s\n", post.ID, post.Title)
    }
    
    // 4. Работа с произвольным JSON
    fmt.Println("\n4. Работа с произвольным JSON")
    
    jsonString := `{
        "message": "Hello World",
        "numbers": [1, 2, 3, 4, 5],
        "nested": {
            "key": "value",
            "bool": true
        }
    }`
    
    var data map[string]interface{}
    err = json.Unmarshal([]byte(jsonString), &data)
    if err != nil {
        fmt.Printf("Ошибка парсинга: %v\n", err)
        return
    }
    
    fmt.Printf("Сообщение: %s\n", data["message"])
    fmt.Printf("Числа: %v\n", data["numbers"])
    
    if nested, ok := data["nested"].(map[string]interface{}); ok {
        fmt.Printf("Вложенный ключ: %s\n", nested["key"])
        fmt.Printf("Вложенный bool: %t\n", nested["bool"])
    }
}

// Функция для получения пользователей из API
func fetchUsers() ([]User, error) {
    resp, err := http.Get("https://jsonplaceholder.typicode.com/users")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    var users []User
    err = json.Unmarshal(body, &users)
    if err != nil {
        return nil, err
    }
    
    return users, nil
}

// Функция для получения постов из API
func fetchPosts() ([]Post, error) {
    resp, err := http.Get("https://jsonplaceholder.typicode.com/posts")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    var posts []Post
    err = json.Unmarshal(body, &posts)
    if err != nil {
        return nil, err
    }
    
    return posts, nil
}