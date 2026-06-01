#include <vector>
#include <algorithm>
#include <thread>
#include <chrono>

#include "randpp.h"

// Базовый абстрактный класс для исполнительного устройства
class Actuator {
public:
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual ~Actuator() = default;
};

// Класс для работы с датчиком
class Sensor {
public:
    // Виртуальный метод для чтения показаний — переопределите в своей реализации
    virtual double read() = 0;
    virtual ~Sensor() = default;
};

// Основной класс системы управления
class ControlSystem {
private:
    std::vector<Actuator*> actuators;
    Sensor* sensor;
    double max_time;           // Максимальное допустимое время работы ИУ
    double stabilization_time; // Время стабилизации системы после изменения
    double test_time;          // Базовое время тестирования ИУ

public:
    // Конструктор
    ControlSystem(Sensor* sens, double max_t = 30.0, double stab_time = 5.0, double t_time = 2.0)
        : sensor(sens), max_time(max_t), stabilization_time(stab_time), test_time(t_time) {
    }

    // Добавление исполнительного устройства в систему
    void addActuator(Actuator* act) {
        actuators.push_back(act);
    }

    // Вариант 1: поочерёдный тест ИУ, поиск оптимального времени работы
    void findOptimalTimeSequential() {
        std::vector<double> optimal_times(actuators.size(), 1.0); // Начальное время работы
        double step = 0.5;
        int direction = 1;
        double prev_value = 0.0;

        while (true) {
            for (size_t i = 0; i < actuators.size(); ++i) {
                // Тестируем текущее ИУ с текущим временем работы
                actuators[i]->start();
                std::this_thread::sleep_for(std::chrono::seconds(static_cast<int>(optimal_times[i])));
                actuators[i]->stop();
                std::this_thread::sleep_for(std::chrono::seconds(static_cast<int>(stabilization_time)));

                double current_value = sensor->read();

                if (current_value > prev_value) {
                    // Улучшение — увеличиваем время работы этого ИУ
                    optimal_times[i] += step * direction;
                    prev_value = current_value;
                }
                else {
                    // Ухудшение — меняем направление поиска и уменьшаем шаг
                    direction = -direction;
                    step *= 0.8;
                    break; // Переходим к следующему циклу
                }

                // Ограничиваем максимальное время работы
                if (optimal_times[i] > max_time) {
                    optimal_times[i] = max_time;
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(1)); // Пауза между циклами
        }
    }

    // Вариант 2: одновременная работа ИУ, адаптивная регулировка времени
    void adaptiveSimultaneousControl() {
        std::vector<double> current_times(actuators.size(), 1.0);
        double step = 0.5;
        double prev_max = 0.0;

        while (true) {
            // Включаем все ИУ на текущие времена
            for (auto act : actuators) {
                act->start();
            }

            // Ждём максимальное из текущих времён работы
            double max_current_time = *std::max_element(current_times.begin(), current_times.end());
            std::this_thread::sleep_for(std::chrono::seconds(static_cast<int>(max_current_time)));

            // Выключаем все ИУ
            for (auto act : actuators) {
                act->stop();
            }

            std::this_thread::sleep_for(std::chrono::seconds(static_cast<int>(stabilization_time)));
            double current_max = sensor->read();

            if (current_max > prev_max) {
                // Улучшение — увеличиваем времена работы всех ИУ
                for (auto& time : current_times) {
                    time += step;
                    if (time > max_time) time = max_time;
                }
                prev_max = current_max;
            }
            else {
                // Ухудшение — уменьшаем времена и уменьшаем шаг
                for (auto& time : current_times) {
                    time -= step * 0.5;
                    if (time < 0) time = 0;
                }
                step *= 0.8;
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    // Вариант 3: перебор стратегий (поочерёдно, вместе, разные комбинации)
    void strategyBasedControl() {
        enum class StrategyType { SINGLE, COMBINED };

        struct Strategy {
            StrategyType type;
            std::vector<size_t> actuator_indices;
            std::vector<double> times;
        };

        std::vector<Strategy> strategies;

        // Создаём стратегии: поочерёдно каждый ИУ и все вместе
        for (size_t i = 0; i < actuators.size(); ++i) {
            strategies.push_back({ StrategyType::SINGLE, {i}, {test_time} });
        }
        if (actuators.size() > 1) {
            std::vector<size_t> all_indices;
            std::vector<double> all_times(actuators.size(), test_time);
            for (size_t i = 0; i < actuators.size(); ++i) {
                all_indices.push_back(i);
            }
            strategies.push_back({ StrategyType::COMBINED, all_indices, all_times });
        }

        double best_result = 0.0;
        Strategy best_strategy = strategies[0];

        while (true) {
            for (const auto& strategy : strategies) {
                if (strategy.type == StrategyType::SINGLE) {
                    size_t idx = strategy.actuator_indices[0];
                    double time = strategy.times[0];

                    actuators[idx]->start();
                    std::this_thread::sleep_for(std::chrono::seconds(static_cast<int>(time)));
                    actuators[idx]->stop();
                    std::this_thread::sleep_for(std::chrono::seconds(static_cast<int>(stabilization_time)));
                }
                else if (strategy.type == StrategyType::COMBINED) {
                    // Включаем все указанные ИУ
                    for (size_t idx : strategy.actuator_indices) {
                        actuators[idx]->start();
                    }
                    // Ждём максимальное время из стратегии
                    double max_time_in_strategy = *std::max_element(strategy.times.begin(), strategy.times.end());
                    std::this_thread::sleep_for(std::chrono::seconds(static_cast<int>(max_time_in_strategy)));
                    // Выключаем все
                    for (size_t idx : strategy.actuator_indices) {
                        actuators[idx]->stop();
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(static_cast<int>(stabilization_time)));
                }

                double result = sensor->read();
                if (result > best_result) {
                    best_result = result;
                    best_strategy = strategy;
                }
            }

            // Применяем лучшую стратегию на длительный период
            if (best_strategy.type == StrategyType::SINGLE) {
                size_t idx = best_strategy.actuator_indices[0];
                double time = best_strategy.times[0];

                actuators[idx]->start();
                std::this_thread::sleep_for(std::chrono::seconds(static_cast<int>(time * 10))); // Длительная работа
                actuators[idx]->stop();
            }
            else if (best_strategy.type == StrategyType::COMBINED) {
                // Включаем все ИУ из лучшей стратегии
                for (size_t idx : best_strategy.actuator_indices) {
                    actuators[idx]->start();
                }
                double max_time_in_best = *std::max_element(best_strategy.times.begin(), best_strategy.times.end());
                std::this_thread::sleep_for(std::chrono::seconds(static_cast<int>(max_time_in_best * 10)));
                // Выключаем все
                for (size_t idx : best_strategy.actuator_indices) {
                    actuators[idx]->stop();
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
};



#include <thread>
#include <atomic>

// Пример конкретной реализации
class EntropyEaterRNG : public Actuator
{
private:
    std::thread worker_thread;
    std::atomic<bool> stop_flag{ false };
    bool is_running{ false };
    RNG* m_rng;
    // Функция, которая будет выполняться в потоке
    void work() {
        while (!stop_flag) 
        {
            std::cerr<<m_rng->generate(32);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

public:
    void start() override 
    {
        if (is_running) {
            return; // Уже запущен
        }
        m_rng = new RNG(time(nullptr), 73.8f);
        stop_flag = false;
        worker_thread = std::thread(&EntropyEaterRNG::work, this);
        is_running = true;
    }

    void stop() override {
        if (!is_running) {
            return; // Не был запущен
        }
        stop_flag = true; // Устанавливаем флаг, чтобы поток завершил работу
        if (worker_thread.joinable()) {
            worker_thread.join(); // Ждем завершения потока
        }
        is_running = false;
    }

    ~EntropyEaterRNG() override {
        stop(); // Гарантируем остановку потока при уничтожении объекта
    }
};
