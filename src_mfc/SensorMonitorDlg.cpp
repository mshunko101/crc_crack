#include "pch.h"
#include "SensorMonitor.h"
#include "SensorMonitorDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define min_prime 1000000
#define max_prime 1000000000


#include <iostream>
#include <string>
#include <map>
#include <cstdlib>
#include <ctime>
#include <thread>
#include <chrono>

// Быстрое возведение в степень по модулю (a^b mod m)
long long mod_exp(long long a, long long b, long long m) {
    long long res = 1;
    a = a % m;
    while (b > 0) {
        if (b & 1) res = (res * a) % m;
        b = b >> 1;
        a = (a * a) % m;
    }
    return res;
}

// Расширенный алгоритм Евклида: возвращает gcd(a,b) и находит x,y: a*x + b*y = gcd
long long ext_gcd(long long a, long long b, long long& x, long long& y) {
    if (b == 0) {
        x = 1; y = 0;
        return a;
    }
    long long x1, y1;
    long long gcd = ext_gcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return gcd;
}

// Обратное по модулю: возвращает d такое, что (e * d) ≡ 1 (mod phi)
long long mod_inv(long long e, long long phi) {
    long long x, y;
    long long g = ext_gcd(e, phi, x, y);
    if (g != 1) return -1; // обратного нет
    return (x % phi + phi) % phi;
}

// «Простой» тест простоты (для маленьких чисел)
bool is_prime(int n) {
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;
    for (int i = 3; i * i <= n; i += 2)
        if (n % i == 0) return false;
    return true;
}

// === УЯЗВИМЫЙ ГПСЧ: слаб в первые 10 секунд ===
class VulnerableRNG {
public:
    static bool is_weak_window; // true в первые 10 сек
    static void seed() {
        srand(static_cast<unsigned int>(time(0) ^ 12345));
    }
    static int rand_int(int low, int high) {
        return low + rand() % (high - low + 1);
    }
};

bool VulnerableRNG::is_weak_window = true;

// Генерация простого числа с использованием уязвимого ГПСЧ
int gen_prime_vuln(int low, int high) {
    int p;
    do {
        p = VulnerableRNG::rand_int(low, high);
    } while (!is_prime(p));
    return p;
}

// Упрощённый хеш для демонстрации
long long simple_hash(const std::wstring& str, long long mod) {
    long long h = 0;
    for (wchar_t c : str) {
        h = (h * 31 + (wchar_t)c) % mod;
    }
    return h;
}

// Упрощённый «сертификат»: просто набор пар «ключ-значение» + подпись
struct SimpleCert {
    std::map<std::wstring, std::wstring> fields; // CN, O, validity, serial и т. д.
    std::wstring signature; // Подпись УЦ в виде строки с числом
};

struct CSR {
    std::map<std::wstring, std::wstring> subject; // Данные владельца: CN=example.com и т. п.
    std::wstring pubkey_n; // Открытый модуль n клиента
    std::wstring pubkey_e; // Открытый показатель e клиента
};

// Создаём самоподписанный сертификат УЦ
SimpleCert generate_root_ca(long long ca_n, long long ca_e, long long ca_d) {
    SimpleCert ca_cert;
    ca_cert.fields[_T("CN")] = _T("My Mini CA");
    ca_cert.fields[_T("validity_start")] = _T("2024-01-01");
    ca_cert.fields[_T("validity_end")] = _T("2034-01-01");
    ca_cert.fields[_T("serial")] = _T("1"); // Серийный номер
    ca_cert.fields[_T("pubkey_n")] = std::to_wstring(ca_n);
    ca_cert.fields[_T("pubkey_e")] = std::to_wstring(ca_e);

    // «Подписываем» сертификат: хешируем поля и подписываем RSA
    std::wstring data_to_sign;
    for (const auto& field : ca_cert.fields) {
        data_to_sign += field.first + _T(":") + field.second + _T("|");
    }
    long long hash_val = simple_hash(data_to_sign, ca_n); // Ваш хеш-метод
    long long sig = mod_exp(hash_val, ca_d, ca_n); // Подпись: hash^d mod n
    ca_cert.signature = std::to_wstring(sig);

    return ca_cert;
}

// Формирование CSR клиентом
CSR create_csr(const std::map<std::wstring, std::wstring>& subject,
    long long client_n, long long client_e) {
    CSR csr;
    csr.subject = subject;
    csr.pubkey_n = std::to_wstring(client_n);
    csr.pubkey_e = std::to_wstring(client_e);
    return csr;
}

// Подписание CSR УЦ
SimpleCert sign_csr(const CSR& csr, const SimpleCert& ca_cert,
    long long ca_d, long long ca_n) {
    SimpleCert client_cert;

    // Копируем данные из CSR
    for (const auto& field : csr.subject) {
        client_cert.fields[field.first] = field.second;
    }

    // Добавляем атрибуты от УЦ
    client_cert.fields[_T("issuer")] = ca_cert.fields.at(_T("CN"));
    client_cert.fields[_T("validity_start")] = _T("2024-01-01");
    client_cert.fields[_T("validity_end")] = _T("2025-01-01");
    client_cert.fields[_T("serial")] = std::to_wstring(rand() % 100000 + 1); // Случайный серийный номер
    client_cert.fields[_T("pubkey_n")] = csr.pubkey_n;
    client_cert.fields[_T("pubkey_e")] = csr.pubkey_e;

    // Подписываем сертификат клиента закрытым ключом УЦ
    std::wstring data_to_sign;
    for (const auto& field : client_cert.fields) {
        data_to_sign += field.first + _T(":") + field.second + _T("|");
    }
    long long hash_val = simple_hash(data_to_sign, ca_n);
    long long sig = mod_exp(hash_val, ca_d, ca_n);
    client_cert.signature = std::to_wstring(sig);

    return client_cert;
}

// Проверка сертификата
bool verify_cert(const SimpleCert& cert, const SimpleCert& ca_cert) {
    // Берём открытый ключ УЦ из его сертификата
    long long ca_pub_n = std::stoll(ca_cert.fields.at(_T("pubkey_n")));
    long long ca_pub_e = std::stoll(ca_cert.fields.at(_T("pubkey_e")));

    // Восстанавливаем хеш из подписи сертификата
    long long sig_val = std::stoll(cert.signature);
    long long recovered_hash = mod_exp(sig_val, ca_pub_e, ca_pub_n);

    // Считаем хеш от полей сертификата
    std::wstring data_to_hash;
    for (const auto& field : cert.fields) {
        data_to_hash += field.first + _T(":") + field.second + _T("|");
    }
    long long actual_hash = simple_hash(data_to_hash, ca_pub_n);

    return recovered_hash == actual_hash;
}

// === АТАКУЮЩИЙ МОДУЛЬ: перебирает семена и восстанавливает ключи ===
class Attacker {
public:
    // Перебираем семена в предполагаемом временном окне (±30 сек от T)
    bool crack_rsa_key(long long n, long long e, time_t approx_time) {
        for (int offset = -30; offset <= 30; ++offset) {
            time_t candidate_seed = approx_time + offset;
            srand(static_cast<unsigned int>(candidate_seed));

            // Пытаемся сгенерировать p и q, которые дадут n
            for (int i = 0; i < 200; ++i) { // 200 попыток на семя
                int p_candidate = gen_prime_trial(min_prime, max_prime); // Диапазон как у УЦ
                int q_candidate = gen_prime_trial(min_prime, max_prime);
                long long n_candidate = (long long)p_candidate * q_candidate;

                if (n_candidate == n) {
                    long long phi = (long long)(p_candidate - 1) * (q_candidate - 1);
                    long long d_cracked = mod_inv(e, phi);
                    return true;
                }
            }
        }
        return false;
    }

private:
    // Вспомогательная функция для генерации простых при переборе
    int gen_prime_trial(int low, int high) {
        int p;
        do {
            p = low + rand() % (high - low + 1); // Используем текущий rand()
        } while (!is_prime(p));
        return p;
    }
};





BEGIN_MESSAGE_MAP(CSensorMonitorDlg, CDialogEx)
    ON_BN_CLICKED(IDC_START, &CSensorMonitorDlg::OnBnClickedStart)
    ON_BN_CLICKED(IDC_STOP, &CSensorMonitorDlg::OnBnClickedStop)
    ON_BN_CLICKED(IDC_RESET, &CSensorMonitorDlg::OnBnClickedReset)
    ON_WM_TIMER()
    ON_WM_CTLCOLOR()
END_MESSAGE_MAP()

CSensorMonitorDlg::CSensorMonitorDlg(CWnd* pParent)
    : CDialogEx(IDD_SENSORMONITOR_DIALOG, pParent)
{
    m_hSerial = INVALID_HANDLE_VALUE;
    m_bRunning = false;
    m_nTimerID = 0;
    m_balance_step = 0;
    m_diffs_step = 0;
    m_prev_value = 0.0;
}

void CSensorMonitorDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_CURRENT_VALUE, m_ctrlCurrentValue);
    DDX_Control(pDX, IDC_CURRENT_DIFF, m_ctrlCurrentDiff);
    DDX_Control(pDX, IDC_MIN_DIFF, m_ctrlMinDiff);
    DDX_Control(pDX, IDC_MAX_DIFF, m_ctrlMaxDiff);
    DDX_Control(pDX, IDC_BALANCE, m_ctrlBalance);
    DDX_Control(pDX, IDC_MIN_VALUE, m_ctrlMinValue);
    DDX_Control(pDX, IDC_MAX_VALUE, m_ctrlMaxValue);
    DDX_Control(pDX, IDC_CONDITION, m_ctrlCondition);
    DDX_Control(pDX, IDC_TIMESTAMP, m_ctrlTimestamp);
}

BOOL CSensorMonitorDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    // Инициализация элементов управления
    m_ctrlCurrentValue.SetWindowText(L"Нет данных");
    m_ctrlCurrentDiff.SetWindowText(L"Недостаточно данных");
    m_ctrlMinDiff.SetWindowText(L"Нет данных");
    m_ctrlMaxDiff.SetWindowText(L"Нет данных");
    m_ctrlBalance.SetWindowText(L"0.00");
    m_ctrlMinValue.SetWindowText(L"Нет данных");
    m_ctrlMaxValue.SetWindowText(L"Нет данных");
    m_ctrlCondition.SetWindowText(L"НЕТ ДАННЫХ");
    m_ctrlTimestamp.SetWindowText(L"");

    return TRUE;
}

void CSensorMonitorDlg::OnBnClickedStart()
{
    StartSerial();
    m_nTimerID = SetTimer(1, 1000, nullptr); // Обновление каждую секунду
}

void CSensorMonitorDlg::OnBnClickedStop()
{
    StopSerial();
    if (m_nTimerID) {
        KillTimer(m_nTimerID);
        m_nTimerID = 0;
    }
}

void CSensorMonitorDlg::OnTimer(UINT_PTR nIDEvent)
{
    if (nIDEvent == 1) {
        ReadSerialData();
        UpdateMetrics();
    }
    CDialogEx::OnTimer(nIDEvent);
}

void CSensorMonitorDlg::StartSerial()
{
    // Открытие COM-порта (замените "COM3" на ваш порт)
    m_hSerial = CreateFile(L"COM6",
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (m_hSerial == INVALID_HANDLE_VALUE) {
        AfxMessageBox(L"Ошибка открытия COM-порта");
        return;
    }

    DCB dcb = { 0 };
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(m_hSerial, &dcb)) {
        AfxMessageBox(L"Ошибка получения настроек COM-порта");
        CloseHandle(m_hSerial);
        m_hSerial = INVALID_HANDLE_VALUE;
        return;
    }

    dcb.BaudRate = CBR_9600;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;

    if (!SetCommState(m_hSerial, &dcb)) {
        AfxMessageBox(L"Ошибка установки настроек COM-порта");
        CloseHandle(m_hSerial);
        m_hSerial = INVALID_HANDLE_VALUE;
        return;
    }

    m_bRunning = true;
}

void CSensorMonitorDlg::StopSerial()
{
    m_bRunning = false;
    if (m_hSerial != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hSerial);
        m_hSerial = INVALID_HANDLE_VALUE;
    }
}

void CSensorMonitorDlg::ReadSerialData()
{
    if (!m_bRunning || m_hSerial == INVALID_HANDLE_VALUE) return;

    DWORD bytesRead;
    CString dataBufferStr;
    SendCommandAndReadResponse(m_hSerial, dataBufferStr);
    double value = std::stod(dataBufferStr.GetBuffer());
    CTime now = CTime::GetCurrentTime();
    m_dataBuffer.push_back({ now, value });
    dataBufferStr.ReleaseBuffer();
}

BOOL CSensorMonitorDlg::SendCommandAndReadResponse(HANDLE hCom, CString& outResponse)
{
    // 1. Очищаем буферы приёма и передачи от старого мусора
    if (!PurgeComm(hCom, PURGE_RXCLEAR | PURGE_TXCLEAR))
    {
        AfxMessageBox(_T("Ошибка очистки буфера COM-порта"));
        return FALSE;
    }
    // 2. Отправляем команду 'G' (запрос данных)
    const char command = 'G';
    DWORD bytesWritten = 0;
    if (!WriteFile(hCom, &command, 1, &bytesWritten, NULL) || bytesWritten != 1)
    {
        AfxMessageBox(_T("Ошибка отправки команды на Arduino"));
        return FALSE;
    }

    // 3. Ждём немного, чтобы Arduino успел сформировать ответ
    // (можно заменить на более умный механизм ожидания по событию)
    Sleep(1500);

    // 4. Читаем ответ от Arduino
    char buffer[256];
    DWORD bytesRead = 0;
    BOOL readResult = ReadFile(hCom, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
  
    if (!readResult || bytesRead == 0)
    {
        outResponse = _T("Нет ответа от Arduino");
        return FALSE;
    }

    // 5. Преобразуем прочитанные байты в CString
    buffer[bytesRead] = '\0'; // Завершаем строку нулём
    outResponse = CString(buffer, bytesRead);

    SetDlgItemText(IDC_STATIC_LABRL, outResponse);

    return TRUE;
}


void CSensorMonitorDlg::ClearOldData()
{
    CTime cutoff = CTime::GetCurrentTime() - CTimeSpan(0, 0, 3, 0); // 3 минуты назад

    while (!m_dataBuffer.empty() && m_dataBuffer.begin()->timestamp < cutoff)
    {
        m_dataBuffer.erase(m_dataBuffer.begin());
    }
}
#include <cmath>
// Структура для хранения вектора (x1, x2, x3)
struct Vector3 {
    double x1, x2, x3;

    // Конструктор
    Vector3(double y) : x1(2.0 * y / 3.0), x2(y / 3.0), x3(y* y) {}

    // Длина вектора
    double length() const {
        return std::sqrt(x1 * x1 + x2 * x2 + x3 * x3);
    }

    // Скалярное произведение с другим вектором
    double dot(const Vector3& other) const {
        return x1 * other.x1 + x2 * other.x2 + x3 * other.x3;
    }

    // Разность векторов
    Vector3 operator-(const Vector3& other) const {
        return Vector3(0, x1 - other.x1, x2 - other.x2, x3 - other.x3);
    }

private:
    // Частный конструктор для разности векторов
    Vector3(int dummy, double dx1, double dx2, double dx3) : x1(dx1), x2(dx2), x3(dx3) {}
};

// Функция для вычисления угла между двумя векторами в градусах
double angle_between(const Vector3& v1, const Vector3& v2) {
    double dot_product = v1.dot(v2);
    double len_product = v1.length() * v2.length();

    if (len_product == 0) return 0.0;

    double cos_theta = dot_product / len_product;
    // Ограничиваем значение для арккосинуса [-1, 1] из-за возможных погрешностей вычислений
    cos_theta = max(-1.0, min(1.0, cos_theta));

    return std::acos(cos_theta) * 180.0 / 3.14159265f;
}

// Функция для вычисления евклидова расстояния между векторами
double euclidean_distance(const Vector3& v1, const Vector3& v2) {
    Vector3 diff = v1 - v2;
    return diff.length();
}

void CSensorMonitorDlg::UpdateMetrics()
{
    ClearOldData();

    // Если нет данных — выводим соответствующие сообщения
    if (m_dataBuffer.empty())
    {
        m_ctrlCurrentValue.SetWindowText(L"Нет данных");
        m_ctrlCurrentDiff.SetWindowText(L"Недостаточно данных");
        m_ctrlMinDiff.SetWindowText(L"Нет данных");
        m_ctrlMaxDiff.SetWindowText(L"Нет данных");
        m_ctrlBalance.SetWindowText(L"0.00");
        m_ctrlMinValue.SetWindowText(L"Нет данных");
        m_ctrlMaxValue.SetWindowText(L"Нет данных");
        m_ctrlCondition.SetWindowText(L"НЕТ ДАННЫХ");
        CString timestamp;
        timestamp.Format(L"Обновлено: %02d:%02d:%02d",
            CTime::GetCurrentTime().GetHour(),
            CTime::GetCurrentTime().GetMinute(),
            CTime::GetCurrentTime().GetSecond());
        m_ctrlTimestamp.SetWindowText(timestamp);
        return;
    }

    // Текущее значение — последнее в буфере
    double currentValue = m_dataBuffer.back().value;
    CString currentValueStr;
    currentValueStr.Format(L"%.2f", currentValue);
    m_ctrlCurrentValue.SetWindowText(currentValueStr);

    // Разница между двумя последними значениями
    double currentDiff = 0.0;
    if (m_dataBuffer.size() >= 2)
    {
        auto it = m_dataBuffer.end();
        --it;
        auto prevIt = it;
        --prevIt;
        currentDiff = it->value - prevIt->value;
        CString diffStr;
        diffStr.Format(L"%.2f", currentDiff);
        m_ctrlCurrentDiff.SetWindowText(diffStr);
    }
    else
    {
        m_ctrlCurrentDiff.SetWindowText(L"Недостаточно данных");
    }

    // Вычисление всех разниц между соседними значениями
    std::vector<double> diffs;
    auto it = m_dataBuffer.begin();
    auto nextIt = it;
    ++nextIt;

    for (; nextIt != m_dataBuffer.end(); ++it, ++nextIt)
    {
        diffs.push_back(nextIt->value - it->value);
    }

    // Минимум и максимум среди разниц
    double minDiff = 0.0, maxDiff = 0.0;
    if (!diffs.empty())
    {
        minDiff = *std::min_element(diffs.begin(), diffs.end());
        maxDiff = *std::max_element(diffs.begin(), diffs.end());

        CString minDiffStr, maxDiffStr;
        minDiffStr.Format(L"%.2f", minDiff);
        maxDiffStr.Format(L"%.2f", maxDiff);
        m_ctrlMinDiff.SetWindowText(minDiffStr);
        m_ctrlMaxDiff.SetWindowText(maxDiffStr);
    }
    else
    {
        m_ctrlMinDiff.SetWindowText(L"Нет данных");
        m_ctrlMaxDiff.SetWindowText(L"Нет данных");
    }

    // Баланс — сумма всех разниц
    double balance = std::accumulate(diffs.begin(), diffs.end(), 0.0);
    CString balanceStr;
    balanceStr.Format(L"%.2f", balance);
    m_ctrlBalance.SetWindowText(balanceStr);

    // Минимум и максимум значений за период
    double minValue = m_dataBuffer.back().value;
    double maxValue = m_dataBuffer.back().value;

    for (const auto& data : m_dataBuffer)
    {
        if (data.value < minValue) minValue = data.value;
        if (data.value > maxValue) maxValue = data.value;
    }

    CString minValueStr, maxValueStr;
    minValueStr.Format(L"%.2f", minValue);
    maxValueStr.Format(L"%.2f", maxValue);
    m_ctrlMinValue.SetWindowText(minValueStr);
    m_ctrlMaxValue.SetWindowText(maxValueStr);

    // Проверка условия balance > 0 && currentDiff < 0
    CString conditionStr;
    COLORREF conditionColor;
    double angle = 0;
    if (m_dataBuffer.size() > 2)
    {
        Vector3 a(m_dataBuffer[m_dataBuffer.size() - 1].value);
        Vector3 b(m_dataBuffer[m_dataBuffer.size() - 2].value);
        angle = angle_between(a, b);
        if (angle_between(a,b) > 0.001)
        {
            conditionStr = L"ВЫПОЛНЕНО";
            conditionColor = RGB(76, 175, 80); // Зелёный  
        }
        else
        {
            auto y = m_dataBuffer[m_dataBuffer.size() - 1].value;
            double x1 = 2 * y / 3;
            double x2 = y / 3;
            double x3 = y * y;
            conditionStr.Format(_T(" x1=%lf   x2=%lf   x3=%lf"), x1, x2, x3);
            conditionColor = RGB(255, 152, 0); // Оранжевый
        } 

    }
    
    m_prev_value = m_dataBuffer[m_dataBuffer.size() - 1].value;
    m_ctrlCondition.SetWindowText(conditionStr);
    // Для изменения цвета текста потребуется дополнительный обработчик WM_CTLCOLOR
            // Обновление временной метки
    CString timestamp;
    timestamp.Format(L"Обновлено: %02d:%02d:%02d | Точек данных: %d  %lf",
        CTime::GetCurrentTime().GetHour(),
        CTime::GetCurrentTime().GetMinute(),
        CTime::GetCurrentTime().GetSecond(),
        m_dataBuffer.size(), angle);
    m_ctrlTimestamp.SetWindowText(timestamp);

}

#include <sstream>

int ca_p = gen_prime_vuln(min_prime, max_prime);
int ca_q = gen_prime_vuln(min_prime, max_prime);


int client_p = gen_prime_vuln(min_prime, max_prime);
int client_q = gen_prime_vuln(min_prime, max_prime);


int is = 0;
void check_func()
{
    std::wstringbuf log_buffer;
    std::wostream log_stream(&log_buffer);
    time_t start_time = time(0);
    log_stream << _T("=== СИМУЛЯЦИЯ АТАКИ НА СЛАБЫЙ ГПСЧ ===\n");
    log_stream << _T("Запуск системы в момент ") << start_time << _T(" (это наша точка отсчёта)\n\n");

      // Включаем уязвимое окно на 5 сек — именно в этот момент будут генерироваться ключи
    VulnerableRNG::is_weak_window = false;
    VulnerableRNG::seed();

    //    log_stream << "--- ГЕНЕРАЦИЯ КЛЮЧЕЙ УЦ В УЯЗВИМЫЙ ПЕРИОД ---\n";
        // Генерируем ключи УЦ в уязвимый период

    long long ca_n = (long long)ca_p * ca_q;
    long long ca_phi = (long long)(ca_p - 1) * (ca_q - 1);
    long long ca_e = 65537;
    while (ext_gcd(ca_e, ca_phi, *(new long long), *(new long long)) != 1) ca_e += 2;
    long long ca_d = mod_inv(ca_e, ca_phi);

    SimpleCert ca_cert = generate_root_ca(ca_n, ca_e, ca_d);
    log_stream << _T("УЦ создан в уязвимый период. n=") << ca_n
    << _T(", p=") << ca_p << _T(", q=") << ca_q << _T("\n");

    // Клиент генерирует ключи уже в «безопасном» режиме
    log_stream << _T("\n--- ГЕНЕРАЦИЯ КЛЮЧЕЙ КЛИЕНТА В НОРМАЛЬНОМ РЕЖИМЕ ---\n");
    VulnerableRNG::seed(); // «Нормальный» seed

    long long client_n = (long long)(client_p * client_q);
    long long client_phi = (long long)(client_p - 1) * (client_q - 1);
    long long client_e = 65537;
    if (client_e >= client_phi) client_e = 3;
    while (ext_gcd(client_e, client_phi, *(new long long), *(new long long)) != 1) client_e += 2;
    long long client_d = mod_inv(client_e, client_phi);

    // Создаём CSR от клиента
    std::map<std::wstring, std::wstring> subject;
    subject[_T("CN")] = _T("client.example.com");
    subject[_T("O")] = _T("Client Org");

    CSR client_csr = create_csr(subject, client_n, client_e);
    //   log_stream << "CSR создан!\n";

       // УЦ подписывает CSR и выдаёт сертификат
    SimpleCert client_cert = sign_csr(client_csr, ca_cert, ca_d, ca_n);
    log_stream << _T("Сертификат клиента выдан!\n");

       // Проверка сертификата клиента с помощью открытого ключа УЦ
    if (verify_cert(client_cert, ca_cert)) 
    {
        log_stream << _T("Проверка сертификата: ПРОЙДЕНА! Сертификат доверен.\n");
    }
    else {
        log_stream << _T("Проверка сертификата: НЕ ПРОЙДЕНА!\n");
        return;
    }

    // === АТАКА НА КЛЮЧ УЦ ===
    log_stream << _T("\n=== ЗАПУСК АТАКИ ") << is++ << _T(" НА КЛЮЧ УЦ ===\n");
    Attacker attacker;
    bool attack_success = attacker.crack_rsa_key(ca_n, ca_e, start_time);

    if (attack_success) {
        log_stream << _T("\n=== АТАКА УСПЕШНА: злоумышленник восстановил закрытый ключ УЦ! ===\n");
        log_stream << _T("Теперь он может подписывать любые сертификаты от имени УЦ.\n");
    }
    else {
        log_stream << _T("\n=== АТАКА НЕ УДАЛАСЬ: ключ УЦ защищён. ===\n");
        return;
    }
    long long evil_n = 0;
    long long evil_e = 0;
    // Демонстрация: что может сделать злоумышленник, если взломал ключ УЦ
    if (attack_success) {
        log_stream << _T("\n--- ДЕМОНСТРАЦИЯ ЗЛОУМЫШЛЕННЫХ ДЕЙСТВИЙ ---\n");
        // Злоумышленник создаёт фальшивый CSR
        std::map<std::wstring, std::wstring> evil_subject;
        evil_subject[_T("CN")] = _T("evil.com");
        evil_subject[_T("O")] = _T("Evil Corp");

        // Генерирует свои ключи (но это не обязательно — он может использовать любые)
        int evil_p = gen_prime_vuln(min_prime, max_prime);
        int evil_q = gen_prime_vuln(min_prime, max_prime);
        evil_n = (long long)(evil_p * evil_q);
        evil_e = 65537;

        CSR evil_csr = create_csr(evil_subject, evil_n, evil_e);

        // Подписывает фальшивый сертификат СВОИМ (восстановленным) ключом УЦ
        SimpleCert evil_cert = sign_csr(evil_csr, ca_cert, ca_d, ca_n);
        log_stream << _T("Злоумышленник выпустил фальшивый сертификат для evil.com!\n");

        // Попытка проверки — в нашей системе она пройдёт, потому что подпись валидна!
        if (verify_cert(evil_cert, ca_cert)) {
            log_stream << _T("Фальшивый сертификат прошёл проверку! Угроза реальна.\n");
        }
    }
    // Клиент подписывает сообщение своим закрытым ключом
    std::wstring message = _T("Hello, CA! This is a secure message.");
    long long msg_hash = simple_hash(message, client_n);
    long long client_signature = mod_exp(msg_hash, client_d, client_n);

    log_stream << _T("\n--- ПРОВЕРКА ПОДПИСИ СООБЩЕНИЯ КЛИЕНТА ---\n");
    log_stream << _T("Сообщение: ") << message << _T("\n");
    log_stream << _T("Подпись клиента: ") << client_signature << _T("\n");

    // Берём открытый ключ клиента из его сертификата
    long long cert_client_n = std::stoll(client_cert.fields.at(_T("pubkey_n")));
    long long cert_client_e = std::stoll(client_cert.fields.at(_T("pubkey_e")));

    // Восстанавливаем хеш из подписи
    long long recovered_hash = mod_exp(client_signature, cert_client_e, cert_client_n);
    // Считаем хеш от оригинального сообщения
    long long actual_hash = simple_hash(message, cert_client_n);

    log_stream << _T("Восстановленный хеш: ") << recovered_hash << _T("\n");
    log_stream << _T("Реальный хеш: ") << actual_hash << _T("\n");

    if (recovered_hash == actual_hash) {
        log_stream << _T("Проверка подписи сообщения: ПРОЙДЕНА! Сообщение не изменено и от доверенного клиента.\n");
    }
    else {
        log_stream << _T("Проверка подписи сообщения: НЕ ПРОЙДЕНА!\n");
    }

    // Демонстрация атаки, если злоумышленник взломал ключ УЦ
    if (attack_success) {
        log_stream << _T("\n--- АТАКА НА ПОДПИСЬ СООБЩЕНИЯ ---\n");
        // Злоумышленник может подделать подпись от имени клиента
        // Он использует свой ключ (или взломанный ключ УЦ) для создания фальшивой подписи

        std::wstring evil_message = _T("Transfer all funds to account 12345");
        long long evil_hash = simple_hash(evil_message, evil_n);
        // Подписываем фальшивое сообщение, выдавая его за клиента
        long long evil_signature = mod_exp(evil_hash, evil_e, evil_n); // Здесь на самом деле нужно использовать d, но для демонстрации

        log_stream << _T("Злоумышленник создал фальшивую подпись для сообщения: ") << evil_message << _T("\n");
        log_stream << _T("Фальшивая подпись: ") << evil_signature << _T("\n");

        // Попытка проверки фальшивой подписи (она не пройдёт, потому что используется другой ключ)
        long long recovered_evil_hash = mod_exp(evil_signature, cert_client_e, cert_client_n);
        long long actual_evil_hash = simple_hash(evil_message, cert_client_n);

        if (recovered_evil_hash == actual_evil_hash) {
            log_stream << _T("Фальшивая подпись прошла проверку! Угроза реализована.\n");
        }
        else {
            log_stream << _T("Фальшивая подпись не прошла проверку. Нужна более тонкая атака.\n");

            // Более изощрённая атака: злоумышленник создаёт сертификат с тем же n, но другим e
            // и использует его для подделки подписи
            std::map<std::wstring, std::wstring> tricky_subject;
            tricky_subject[_T("CN")] = _T("trusted.com");
            tricky_subject[_T("O")] = _T("Trusted Org");

            CSR tricky_csr = create_csr(tricky_subject, cert_client_n, 3); // Используем тот же n, но e=3
            SimpleCert tricky_cert = sign_csr(tricky_csr, ca_cert, ca_d, ca_n);

            // Теперь подпись, созданная с e=3, может быть проверена с использованием сертификата
            long long tricky_signature = mod_exp(evil_hash, 3, cert_client_n); // Подпись с маленьким e

            long long recovered_tricky_hash = mod_exp(tricky_signature, 3, cert_client_n);
            if (recovered_tricky_hash == actual_evil_hash) {
                log_stream << _T("Изощрённая подделка подписи прошла проверку! Критическая уязвимость.\n");
                MessageBox(0, log_buffer.str().c_str(), _T("ВЗЛОМАНО!"), MB_ICONERROR);
            }
            else {
                log_stream << _T("Изощрённая подделка не удалась.\n");

            }
        }
    }
}


HBRUSH CSensorMonitorDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
    HBRUSH hbr = CDialogEx::OnCtlColor(pDC, pWnd, nCtlColor);

    // Если это наш контрол с условием
    if (pWnd->GetDlgCtrlID() == IDC_CONDITION)
    {
        CString text;
        m_ctrlCondition.GetWindowText(text);

        if (text == L"ВЫПОЛНЕНО")
        {
            check_func();
            pDC->SetTextColor(RGB(76, 175, 80)); // Зелёный
        }
        else if (text == L"НЕ ВЫПОЛНЕНО")
        {
            pDC->SetTextColor(RGB(255, 152, 0)); // Оранжевый
        }
        else // "НЕТ ДАННЫХ"
        {
            pDC->SetTextColor(RGB(128, 128, 128)); // Серый
        }
    }

    return hbr;
}

void CSensorMonitorDlg::OnBnClickedReset()
{
    m_prev_value = 0;
}

