# Первые шаги в изучении Go

Привет! Ты хочешь изучить Go? Отлично! Вот план действий:

## Шаг 1: Установка Go

### macOS
```bash
brew install go
```

### Linux
```bash
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Windows
Скачай и установи с https://go.dev/dl/

### Проверь установку
```bash
go version
```

## Шаг 2: Изучение основ

1. **Начни с простого** - запусти примеры из папки `examples/01-basics/`
2. **Изучи синтаксис** - переменные, функции, структуры
3. **Поэкспериментируй** - измени код и посмотри, что происходит

## Шаг 3: Практика

1. **HTTP клиент** - `examples/02-http-client/`
2. **JSON** - `examples/03-json/`
3. **Файлы** - `examples/04-files/`
4. **Параллельность** - `examples/05-concurrency/`

## Шаг 4: Реальный проект

Попробуй Go версию нашего health check инструмента:
```bash
cd go-healthcheck
go run cmd/healthcheck/main.go -help
```

## Шаг 5: Ресурсы для изучения

- [Go Tour](https://go.dev/tour/) - официальный интерактивный тур
- [Go by Example](https://gobyexample.com/) - примеры кода
- [Effective Go](https://go.dev/doc/effective_go) - лучшие практики

## Советы для успешного изучения

1. **Практикуйся каждый день** - хотя бы 30 минут
2. **Читай чужой код** - изучай проекты на GitHub
3. **Пиши код** - создай свои проекты
4. **Задавай вопросы** - используй форумы и чаты
5. **Не бойся ошибок** - они помогают учиться

## Что дальше?

После освоения основ:
- Веб-разработка с Gin/Echo
- Microservices
- База данных (PostgreSQL, MongoDB)
- Docker и Kubernetes
- gRPC и протоколы
- Тестирование

**Удачи в изучении Go! 🚀**

---

*Если у тебя есть вопросы - не стесняйся спрашивать!*