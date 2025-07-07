// Пример работы с файлами
package main

import (
    "bufio"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

// Структура для статистики файла
type FileStats struct {
    Lines int
    Words int
    Chars int
}

func main() {
    fmt.Println("=== Работа с файлами в Go ===")
    
    // 1. Создание файла и запись данных
    fmt.Println("\n1. Создание файла и запись данных")
    
    filename := "example.txt"
    content := `Привет, мир!
Это пример файла на Go.
Мы изучаем работу с файлами.
Go - отличный язык программирования!`
    
    err := writeFile(filename, content)
    if err != nil {
        fmt.Printf("Ошибка записи файла: %v\n", err)
        return
    }
    
    fmt.Printf("Файл '%s' создан успешно\n", filename)
    
    // 2. Чтение файла
    fmt.Println("\n2. Чтение файла")
    
    data, err := readFile(filename)
    if err != nil {
        fmt.Printf("Ошибка чтения файла: %v\n", err)
        return
    }
    
    fmt.Printf("Содержимое файла:\n%s\n", data)
    
    // 3. Чтение файла построчно
    fmt.Println("\n3. Чтение файла построчно")
    
    lines, err := readFileLines(filename)
    if err != nil {
        fmt.Printf("Ошибка чтения файла по строкам: %v\n", err)
        return
    }
    
    fmt.Printf("Файл содержит %d строк:\n", len(lines))
    for i, line := range lines {
        fmt.Printf("%d: %s\n", i+1, line)
    }
    
    // 4. Статистика файла
    fmt.Println("\n4. Статистика файла")
    
    stats, err := getFileStats(filename)
    if err != nil {
        fmt.Printf("Ошибка получения статистики: %v\n", err)
        return
    }
    
    fmt.Printf("Статистика файла '%s':\n", filename)
    fmt.Printf("Строк: %d\n", stats.Lines)
    fmt.Printf("Слов: %d\n", stats.Words)
    fmt.Printf("Символов: %d\n", stats.Chars)
    
    // 5. Добавление данных в файл
    fmt.Println("\n5. Добавление данных в файл")
    
    additionalContent := "\nЭта строка добавлена позже.\nИ эта тоже!"
    
    err = appendToFile(filename, additionalContent)
    if err != nil {
        fmt.Printf("Ошибка добавления в файл: %v\n", err)
        return
    }
    
    fmt.Printf("Данные добавлены в файл '%s'\n", filename)
    
    // Читаем обновленный файл
    updatedData, err := readFile(filename)
    if err != nil {
        fmt.Printf("Ошибка чтения обновленного файла: %v\n", err)
        return
    }
    
    fmt.Printf("Обновленное содержимое файла:\n%s\n", updatedData)
    
    // 6. Работа с директориями
    fmt.Println("\n6. Работа с директориями")
    
    dirName := "test_directory"
    err = os.Mkdir(dirName, 0755)
    if err != nil && !os.IsExist(err) {
        fmt.Printf("Ошибка создания директории: %v\n", err)
        return
    }
    
    fmt.Printf("Директория '%s' создана\n", dirName)
    
    // Создаем файлы в директории
    for i := 1; i <= 3; i++ {
        fileName := filepath.Join(dirName, fmt.Sprintf("file%d.txt", i))
        err := writeFile(fileName, fmt.Sprintf("Содержимое файла %d", i))
        if err != nil {
            fmt.Printf("Ошибка создания файла %s: %v\n", fileName, err)
            continue
        }
        fmt.Printf("Создан файл: %s\n", fileName)
    }
    
    // Список файлов в директории
    files, err := listFiles(dirName)
    if err != nil {
        fmt.Printf("Ошибка чтения директории: %v\n", err)
        return
    }
    
    fmt.Printf("Файлы в директории '%s':\n", dirName)
    for _, file := range files {
        fmt.Printf("- %s\n", file)
    }
    
    // 7. Очистка
    fmt.Println("\n7. Очистка")
    
    // Удаляем созданные файлы
    os.Remove(filename)
    os.RemoveAll(dirName)
    
    fmt.Println("Временные файлы удалены")
}

// Функция для записи строки в файл
func writeFile(filename, content string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    _, err = file.WriteString(content)
    return err
}

// Функция для чтения всего файла
func readFile(filename string) (string, error) {
    data, err := os.ReadFile(filename)
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// Функция для чтения файла построчно
func readFileLines(filename string) ([]string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    
    var lines []string
    scanner := bufio.NewScanner(file)
    
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }
    
    if err := scanner.Err(); err != nil {
        return nil, err
    }
    
    return lines, nil
}

// Функция для получения статистики файла
func getFileStats(filename string) (*FileStats, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    
    stats := &FileStats{}
    scanner := bufio.NewScanner(file)
    
    for scanner.Scan() {
        line := scanner.Text()
        stats.Lines++
        stats.Chars += len(line) + 1 // +1 для символа новой строки
        
        words := strings.Fields(line)
        stats.Words += len(words)
    }
    
    if err := scanner.Err(); err != nil {
        return nil, err
    }
    
    return stats, nil
}

// Функция для добавления данных в файл
func appendToFile(filename, content string) error {
    file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        return err
    }
    defer file.Close()
    
    _, err = file.WriteString(content)
    return err
}

// Функция для получения списка файлов в директории
func listFiles(dirname string) ([]string, error) {
    file, err := os.Open(dirname)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    
    fileInfos, err := file.Readdir(-1)
    if err != nil {
        return nil, err
    }
    
    var files []string
    for _, fileInfo := range fileInfos {
        if !fileInfo.IsDir() {
            files = append(files, fileInfo.Name())
        }
    }
    
    return files, nil
}