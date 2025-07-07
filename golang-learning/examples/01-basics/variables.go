// Пример 1: Переменные и типы данных
package main

import "fmt"

func main() {
    // Основные типы данных
    var name string = "Darkhan"
    var age int = 25
    var height float64 = 1.75
    var isStudent bool = true
    
    // Краткое объявление переменных
    city := "Алматы"
    country := "Казахстан"
    
    // Константы
    const pi = 3.14159
    const greeting = "Добро пожаловать!"
    
    fmt.Println("=== Основная информация ===")
    fmt.Printf("Имя: %s\n", name)
    fmt.Printf("Возраст: %d лет\n", age)
    fmt.Printf("Рост: %.2f м\n", height)
    fmt.Printf("Студент: %t\n", isStudent)
    fmt.Printf("Город: %s\n", city)
    fmt.Printf("Страна: %s\n", country)
    
    fmt.Printf("\nПи = %.5f\n", pi)
    fmt.Println(greeting)
    
    // Массивы и срезы
    var numbers [5]int = [5]int{1, 2, 3, 4, 5}
    colors := []string{"красный", "зеленый", "синий"}
    
    fmt.Println("\n=== Коллекции ===")
    fmt.Printf("Числа: %v\n", numbers)
    fmt.Printf("Цвета: %v\n", colors)
    
    // Добавление элементов в срез
    colors = append(colors, "желтый")
    fmt.Printf("Цвета после добавления: %v\n", colors)
    
    // Карты (maps)
    person := map[string]interface{}{
        "name":    "Darkhan",
        "age":     25,
        "city":    "Алматы",
        "student": true,
    }
    
    fmt.Println("\n=== Карта ===")
    for key, value := range person {
        fmt.Printf("%s: %v\n", key, value)
    }
}