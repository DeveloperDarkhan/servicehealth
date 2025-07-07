# Изучение Go (Golang) - Руководство для начинающих

Добро пожаловать в руководство по изучению языка программирования Go! Это руководство поможет вам начать изучение Go с нуля и создать практический проект.

## Содержание

1. [Установка Go](#установка-go)
2. [Основы языка](#основы-языка)
3. [Практические примеры](#практические-примеры)
4. [Создание проекта Health Check на Go](#создание-проекта-health-check-на-go)
5. [Ресурсы для дальнейшего изучения](#ресурсы-для-дальнейшего-изучения)

## Установка Go

### Linux/macOS
```bash
# Загрузить Go с официального сайта
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz

# Извлечь архив
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz

# Добавить в PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Windows
1. Скачайте установщик с [официального сайта](https://go.dev/dl/)
2. Запустите установщик и следуйте инструкциям

### Проверка установки
```bash
go version
```

## Основы языка

### 1. Ваша первая программа на Go

Создайте файл `hello.go`:
```go
package main

import "fmt"

func main() {
    fmt.Println("Привет, мир!")
}
```

Запустите:
```bash
go run hello.go
```

### 2. Переменные и типы данных

```go
package main

import "fmt"

func main() {
    // Объявление переменных
    var name string = "Darkhan"
    var age int = 25
    var isStudent bool = true
    
    // Краткое объявление
    city := "Алматы"
    
    fmt.Printf("Имя: %s, Возраст: %d, Студент: %t, Город: %s\n", name, age, isStudent, city)
}
```

### 3. Функции

```go
package main

import "fmt"

// Функция сложения
func add(a, b int) int {
    return a + b
}

// Функция с множественным возвратом
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, fmt.Errorf("деление на ноль")
    }
    return a / b, nil
}

func main() {
    result := add(5, 3)
    fmt.Println("Сумма:", result)
    
    quotient, err := divide(10, 2)
    if err != nil {
        fmt.Println("Ошибка:", err)
    } else {
        fmt.Println("Частное:", quotient)
    }
}
```

### 4. Структуры

```go
package main

import "fmt"

// Определение структуры
type Person struct {
    Name    string
    Age     int
    Email   string
}

// Метод для структуры
func (p Person) Greet() {
    fmt.Printf("Привет, меня зовут %s, мне %d лет\n", p.Name, p.Age)
}

func main() {
    // Создание экземпляра структуры
    person := Person{
        Name:  "Darkhan",
        Age:   25,
        Email: "darkhan@example.com",
    }
    
    person.Greet()
}
```

### 5. Работа с ошибками

```go
package main

import (
    "fmt"
    "strconv"
)

func parseNumber(s string) (int, error) {
    num, err := strconv.Atoi(s)
    if err != nil {
        return 0, fmt.Errorf("не удалось преобразовать '%s' в число: %v", s, err)
    }
    return num, nil
}

func main() {
    // Правильный случай
    num, err := parseNumber("42")
    if err != nil {
        fmt.Println("Ошибка:", err)
    } else {
        fmt.Println("Число:", num)
    }
    
    // Случай с ошибкой
    _, err = parseNumber("не число")
    if err != nil {
        fmt.Println("Ошибка:", err)
    }
}
```

## Практические примеры

В папке `examples/` вы найдете:
- `01-basics/` - Основы языка
- `02-http-client/` - HTTP клиент
- `03-json/` - Работа с JSON
- `04-files/` - Работа с файлами
- `05-concurrency/` - Параллельность (goroutines)

## Создание проекта Health Check на Go

Мы создадим упрощенную версию текущего Python проекта на Go для практики.

### Структура проекта:
```
golang-learning/
├── cmd/
│   └── healthcheck/
│       └── main.go
├── pkg/
│   ├── checker/
│   │   └── checker.go
│   └── logger/
│       └── logger.go
├── go.mod
└── go.sum
```

Смотрите файлы в папке `go-healthcheck/` для полной реализации.

## Ресурсы для дальнейшего изучения

### Официальные ресурсы:
- [Go Tour](https://go.dev/tour/) - Интерактивный тур по Go
- [Go Documentation](https://go.dev/doc/) - Официальная документация
- [Effective Go](https://go.dev/doc/effective_go) - Лучшие практики

### Книги:
- "The Go Programming Language" - Alan Donovan, Brian Kernighan
- "Go in Action" - William Kennedy
- "Concurrency in Go" - Katherine Cox-Buday

### Онлайн курсы:
- [Go by Example](https://gobyexample.com/) - Примеры кода
- [Tour of Go на русском](https://tour.golang-book.ru/)

### Практические проекты:
1. HTTP сервер
2. REST API
3. Microservices
4. CLI инструменты
5. Работа с базами данных

## Следующие шаги

1. Пройдите Go Tour
2. Изучите примеры в папке `examples/`
3. Создайте свой собственный проект
4. Изучите стандартную библиотеку Go
5. Практикуйтесь с goroutines и channels
6. Изучите тестирование в Go

Удачи в изучении Go! 🚀