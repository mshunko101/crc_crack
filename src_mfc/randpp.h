#pragma once
// MSHUNKO 2026
#define _USE_MATH_DEFINES
#include <iostream>
#include <cmath>
#include <iomanip>
#include <math.h>
#include <bitset>
#include <cstdlib>
#include <string>
#include <chrono>
#include <vector>
#include <numeric>
#include <map>
#include <algorithm>
#include <random>
#include <fstream>
#include <ctime>
#include <stdexcept>
#include <unordered_set>
#include <cstdint>



using namespace std;

// Структура для хранения координат точки
struct Point {
    double x, y, z;
    Point(double x = 0, double y = 0, double z = 0) : x(x), y(y), z(z) {}
};

class RotationCalculator {
private:
    Point A, B, O_okr;
    double time_AB;

    // Вспомогательные методы
    Point vectorBetween(const Point& p1, const Point& p2) const {
        return Point(p1.x - p2.x, p1.y - p2.y, p1.z - p2.z);
    }

    double dotProduct(const Point& v1, const Point& v2) const {
        return v1.x * v2.x + v1.y * v2.y + v1.z * v2.z;
    }

    double vectorLength(const Point& v) const {
        return sqrt(v.x * v.x + v.y * v.y + v.z * v.z);
    }

    // Расчётные методы
    Point calculateOA() const {
        return vectorBetween(A, O_okr);
    }

    Point calculateOB() const {
        return vectorBetween(B, O_okr);
    }

    double calculateAngle() const {
        Point OA = calculateOA();
        Point OB = calculateOB();

        double dot_product = dotProduct(OA, OB);
        double length_OA = vectorLength(OA);
        double length_OB = vectorLength(OB);

        double cos_angle = dot_product / (length_OA * length_OB);
        return acos(cos_angle);
    }

    double calculateOmega() const {
        double angle = calculateAngle();
        return angle / time_AB;
    }

public:
    // Конструктор с инициализацией данных
    RotationCalculator(const Point& a, const Point& b, const Point& o, double t)
        : A(a), B(b), O_okr(o), time_AB(t) {
    }

    RotationCalculator(double time)
    {
        A = Point(-3, -0.5, -2.5);
        B = Point(-5.0 / 3.00, -5.0 / 6.00, 25.0 / 4.00);
        O_okr = Point(-2.64, -7.91, 1.65);
        time_AB = time;
    }

    // Метод получения периода вращения
    double getPeriod() const {
        double omega = calculateOmega();
        return 2 * M_PI / omega;
    }

    // Метод для вывода всех результатов
    void showResults() const {
        cout << fixed << setprecision(2);
        cout << "Результаты расчёта:\n";

        Point OA = calculateOA();
        Point OB = calculateOB();

        cout << "Длина вектора OA: " << vectorLength(OA) << "\n";
        cout << "Длина вектора OB: " << vectorLength(OB) << "\n";
        cout << "Угол между векторами (рад): " << calculateAngle() << "\n";
        cout << "Угловая скорость (рад/год): " << calculateOmega() << "\n";
        cout << "Период вращения (лет): " << getPeriod() << "\n";
    }
};

// Первое ядро - ассоциативность
class AssociativityCore {
private:
    unsigned int seed;
public:
    AssociativityCore(unsigned int s) : seed(s) {}

    unsigned int generate() {
        seed = (seed * 1103515245 + 12345) % UINT_MAX;
        return seed;
    }
};

// Второе ядро - среднее значение
class MeanCore {
private:
    double mean;
    std::uniform_real_distribution<> dist;
    std::mt19937 gen;
public:
    MeanCore(double m = 1.0) : mean(m), dist(0.0, 1.0), gen(static_cast<unsigned int>(std::time(0))) {}

    double adjust(unsigned int base) {
        return (base / static_cast<double>(UINT_MAX)) * mean + dist(gen) * 0.1;
    }
};

// Третье ядро - фантазия (содержит несколько под-ядер)
class FantasyCore {
private:
    std::mt19937 gen;
public:
    std::vector<std::vector<int>> dimensions;

    FantasyCore() : gen(static_cast<unsigned int>(std::time(0))) {}

    void add_collision(unsigned int a, unsigned int b) {
        if (a == b) return;  // Пропускаем идентичные значения

        std::bitset<32> bits_a(a);
        std::bitset<32> bits_b(b);

        for (int i = 0; i < 32; i++) {
            if (bits_a[i] != bits_b[i]) {  // Обрабатываем только различающиеся биты
                if (std::find(dimensions.begin(), dimensions.end(),
                    std::vector<int>{bits_a[i] ? 1 : 0, bits_b[i] ? 0 : 1}) == dimensions.end()) {
                    dimensions.push_back({
                        bits_a[i] ? 1 : 0,
                        bits_b[i] ? 0 : 1
                        });
                }
            }
        }
    }

    double apply_fantasy(double base) {
        for (const auto& dim : dimensions) {
            if (std::uniform_int_distribution<>(0, 1)(gen) == 0) {
                base += dim[0] * 0.01;
            }
            else {
                base += dim[1] * 0.01;
            }
        }
        return base;
    }
};
#ifdef APPLICATION
// Основной класс генератора
class RNG : public RNGAbstract {
#else
class RNG 
{
#endif
private:
    AssociativityCore assocCore;
    MeanCore meanCore;
    FantasyCore fantasyCore;
    std::unordered_set<unsigned int> history;  // Буфер истории
    const int MAX_RETRIES = 49;  // Максимальное число попыток перегенерации
    const int MAX_HISTORY_SIZE = 49;  // Максимальный размер истории
    size_t inc_counter;
    size_t inc_max;
public:
    RNG(unsigned int seed, double period) : assocCore(seed), meanCore(), fantasyCore()
    {
        RotationCalculator rc(period);
        inc_max = (size_t) round((rc.getPeriod() * 365.25 * 24 * 3600)/8.0);
    }
    size_t get_period() 
    {
        return inc_max;
    }
    bool isCollision(unsigned int value) {
        if (history.count(value) > 0) {
            return true;
        }
        history.insert(value);
        return false;
    }

    void handle_collision(unsigned int a, unsigned int b) {
        fantasyCore.add_collision(a, b);
    }

    double generate(size_t size)  {
        if (inc_counter >= inc_max)
        {
            assocCore = AssociativityCore(static_cast<unsigned int>(time(nullptr)));
            meanCore = MeanCore();
            fantasyCore = FantasyCore();
            inc_counter = 0;
        }
        inc_counter += size;
        unsigned int base = assocCore.generate();
        int retries = 0;
        unsigned int previous_base = base;  // Сохраняем предыдущее значение для обработки коллизии

        // Обработка коллизий
        while (isCollision(base) && retries < MAX_RETRIES) {
            previous_base = base;  // Сохраняем предыдущее значение
            base = assocCore.generate();  // Перегенерация при коллизии

            // Если столкнулись с той же коллизией, обрабатываем её
            if (base == previous_base) {
                handle_collision(previous_base, base);
            }

            retries++;
        }

        if (retries >= MAX_RETRIES) {
            // Если превышено максимальное число попыток, обновляем seed
            assocCore = AssociativityCore(static_cast<unsigned int>(std::time(0)));
            base = assocCore.generate();

            // Очищаем историю и паттерны коллизий
            clearHistory();
            fantasyCore.dimensions.clear();
        }

        // Проверяем, не превысили ли мы размер истории
        if (getHistorySize() >= MAX_HISTORY_SIZE) {
            // Очищаем историю и паттерны коллизий
            clearHistory();
            fantasyCore.dimensions.clear();
        }

        double mean_adjusted = meanCore.adjust(base);
        double current = fantasyCore.apply_fantasy(mean_adjusted);

        return current;
    }

    // Метод для очистки истории
    void clearHistory() {
        history.clear();
    }

    // Метод для получения размера истории
    size_t getHistorySize() const {
        return history.size();
    }

    // Метод для сброса генератора
    void reset() {
        assocCore = AssociativityCore(static_cast<unsigned int>(std::time(0)));
        clearHistory();
        fantasyCore.dimensions.clear();
    }
};
