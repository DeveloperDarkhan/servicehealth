// Пример 2: Функции
package main

import (
    "fmt"
    "math"
)

// Простая функция
func greet(name string) {
    fmt.Printf("Привет, %s!\n", name)
}

// Функция с возвращаемым значением
func add(a, b int) int {
    return a + b
}

// Функция с множественным возвратом
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, fmt.Errorf("ошибка: деление на ноль")
    }
    return a / b, nil
}

// Функция с именованными возвращаемыми значениями
func rectangle(width, height float64) (area, perimeter float64) {
    area = width * height
    perimeter = 2 * (width + height)
    return // возвращает именованные значения
}

// Вариативная функция (принимает переменное количество аргументов)
func sum(numbers ...int) int {
    total := 0
    for _, num := range numbers {
        total += num
    }
    return total
}

// Функция высшего порядка
func calculate(a, b float64, operation func(float64, float64) float64) float64 {
    return operation(a, b)
}

func main() {
    fmt.Println("=== Примеры функций ===")
    
    // Вызов простой функции
    greet("Darkhan")
    
    // Функция с возвращаемым значением
    result := add(10, 5)
    fmt.Printf("10 + 5 = %d\n", result)
    
    // Функция с обработкой ошибок
    quotient, err := divide(10, 2)
    if err != nil {
        fmt.Printf("Ошибка: %v\n", err)
    } else {
        fmt.Printf("10 / 2 = %.2f\n", quotient)
    }
    
    // Пример с ошибкой
    _, err = divide(10, 0)
    if err != nil {
        fmt.Printf("Ошибка: %v\n", err)
    }
    
    // Функция с именованными возвращаемыми значениями
    area, perimeter := rectangle(5, 3)
    fmt.Printf("Прямоугольник 5x3: площадь = %.2f, периметр = %.2f\n", area, perimeter)
    
    // Вариативная функция
    total := sum(1, 2, 3, 4, 5)
    fmt.Printf("Сумма 1,2,3,4,5 = %d\n", total)
    
    // Функции высшего порядка
    multiply := func(a, b float64) float64 {
        return a * b
    }
    
    subtract := func(a, b float64) float64 {
        return a - b
    }
    
    fmt.Printf("5 * 3 = %.2f\n", calculate(5, 3, multiply))
    fmt.Printf("5 - 3 = %.2f\n", calculate(5, 3, subtract))
    
    // Анонимная функция
    fmt.Printf("Квадратный корень из 16 = %.2f\n", 
        func(x float64) float64 { return math.Sqrt(x) }(16))
}