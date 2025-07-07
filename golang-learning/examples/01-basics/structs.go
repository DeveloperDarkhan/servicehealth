// Пример 3: Структуры и методы
package main

import (
    "fmt"
    "math"
)

// Определение структуры
type Person struct {
    Name    string
    Age     int
    Email   string
    City    string
}

// Метод для структуры Person
func (p Person) Greet() {
    fmt.Printf("Привет! Меня зовут %s, мне %d лет\n", p.Name, p.Age)
}

// Метод с указателем на структуру (может изменять данные)
func (p *Person) HaveBirthday() {
    p.Age++
    fmt.Printf("%s теперь %d лет!\n", p.Name, p.Age)
}

// Метод, возвращающий значение
func (p Person) GetFullInfo() string {
    return fmt.Sprintf("Имя: %s, Возраст: %d, Email: %s, Город: %s", 
        p.Name, p.Age, p.Email, p.City)
}

// Геометрические фигуры
type Circle struct {
    Radius float64
}

type Rectangle struct {
    Width  float64
    Height float64
}

// Методы для Circle
func (c Circle) Area() float64 {
    return math.Pi * c.Radius * c.Radius
}

func (c Circle) Perimeter() float64 {
    return 2 * math.Pi * c.Radius
}

// Методы для Rectangle
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}

func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}

// Интерфейс
type Shape interface {
    Area() float64
    Perimeter() float64
}

// Функция, принимающая любую фигуру
func printShapeInfo(s Shape) {
    fmt.Printf("Площадь: %.2f, Периметр: %.2f\n", s.Area(), s.Perimeter())
}

// Встроенные структуры (embedding)
type Employee struct {
    Person   // встроенная структура
    Position string
    Salary   float64
}

func main() {
    fmt.Println("=== Структуры и методы ===")
    
    // Создание экземпляра структуры
    person := Person{
        Name:  "Darkhan",
        Age:   25,
        Email: "darkhan@example.com",
        City:  "Алматы",
    }
    
    // Вызов методов
    person.Greet()
    fmt.Println(person.GetFullInfo())
    
    // Изменение данных через метод с указателем
    person.HaveBirthday()
    
    fmt.Println("\n=== Геометрические фигуры ===")
    
    // Создание фигур
    circle := Circle{Radius: 5}
    rectangle := Rectangle{Width: 10, Height: 6}
    
    fmt.Println("Круг с радиусом 5:")
    printShapeInfo(circle)
    
    fmt.Println("Прямоугольник 10x6:")
    printShapeInfo(rectangle)
    
    fmt.Println("\n=== Встроенные структуры ===")
    
    // Создание сотрудника
    employee := Employee{
        Person: Person{
            Name:  "Айгерим",
            Age:   28,
            Email: "aigerim@company.com",
            City:  "Астана",
        },
        Position: "Разработчик",
        Salary:   150000,
    }
    
    // Можем обращаться к методам встроенной структуры
    employee.Greet()
    fmt.Printf("Должность: %s, Зарплата: %.0f тенге\n", employee.Position, employee.Salary)
    
    // Можем обращаться к полям встроенной структуры напрямую
    fmt.Printf("Email: %s\n", employee.Email)
}