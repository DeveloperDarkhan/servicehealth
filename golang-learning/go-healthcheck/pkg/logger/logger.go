// Package logger предоставляет функции для логирования
package logger

import (
    "fmt"
    "log"
    "os"
    "time"
)

// LogLevel определяет уровень логирования
type LogLevel int

const (
    INFO LogLevel = iota
    WARNING
    ERROR
)

// Logger представляет логгер с настройками
type Logger struct {
    file   *os.File
    logger *log.Logger
}

// NewLogger создает новый логгер с записью в файл
func NewLogger(filename string) (*Logger, error) {
    file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        return nil, fmt.Errorf("не удалось создать файл лога: %v", err)
    }
    
    logger := log.New(file, "", 0) // Убираем стандартный формат, создаем свой
    
    return &Logger{
        file:   file,
        logger: logger,
    }, nil
}

// logMessage записывает сообщение с определенным уровнем
func (l *Logger) logMessage(level LogLevel, action, message string) {
    now := time.Now().Format("2006-01-02 15:04:05")
    
    var levelStr string
    switch level {
    case INFO:
        levelStr = "INFO"
    case WARNING:
        levelStr = "WARNING"
    case ERROR:
        levelStr = "ERROR"
    }
    
    logEntry := fmt.Sprintf("[%s] [%s] [%s] - %s", now, levelStr, action, message)
    l.logger.Println(logEntry)
}

// Info записывает информационное сообщение
func (l *Logger) Info(action, message string) {
    l.logMessage(INFO, action, message)
}

// Warning записывает предупреждение
func (l *Logger) Warning(action, message string) {
    l.logMessage(WARNING, action, message)
}

// Error записывает ошибку
func (l *Logger) Error(action, message string) {
    l.logMessage(ERROR, action, message)
}

// InfoF записывает информационное сообщение с форматированием
func (l *Logger) InfoF(action, format string, args ...interface{}) {
    message := fmt.Sprintf(format, args...)
    l.Info(action, message)
}

// WarningF записывает предупреждение с форматированием
func (l *Logger) WarningF(action, format string, args ...interface{}) {
    message := fmt.Sprintf(format, args...)
    l.Warning(action, message)
}

// ErrorF записывает ошибку с форматированием
func (l *Logger) ErrorF(action, format string, args ...interface{}) {
    message := fmt.Sprintf(format, args...)
    l.Error(action, message)
}

// Close закрывает файл лога
func (l *Logger) Close() error {
    return l.file.Close()
}