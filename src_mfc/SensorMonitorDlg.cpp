#include "pch.h"
#undef min
#undef max
#include "../uint256_t/uint256_t.h"
#include "SensorMonitor.h"
#include "SensorMonitorDlg.h" 
#include <thread>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

typedef uint256_t sing_value_type;

const sing_value_type step_prime = (unsigned long long)sqrt(std::numeric_limits<unsigned long long>::max());

const sing_value_type min_prime_start = 2;

sing_value_type min_prime = 2;
sing_value_type max_prime = std::numeric_limits<unsigned long long>::max();


std::string to_string(sing_value_type vt)
{
    return vt.str();
}


const sing_value_type zero(0);
#include <iostream>
#include <string>
#include <map>
#include <cstdlib>
#include <ctime>
#include <thread>
#include <chrono>
#include <locale>
#include <codecvt>

std::wstring string_to_wstring(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

sing_value_type isqrt(sing_value_type n) {
    if (n == zero) return 0;
    sing_value_type lo = 1, hi = n;
    // можно ускорить hi: если n > 0, то корень <= n/2+1, но для простоты оставим так
    sing_value_type ans = 1;

    while (lo <= hi) {
        sing_value_type mid = lo + (hi - lo) / 2;
        // mid * mid может переполнить 256 бит, поэтому нужна защита
        // самый простой способ для отладки: взять модуль побольше или временно использовать 128-битные тесты
        // здесь сделаем аккуратно: если mid > n / mid, то mid*mid > n
        if (mid > n / mid) {
            hi = mid - 1;
        }
        else {
            ans = mid;
            lo = mid + 1;
        }
    }
    return ans;
}


// Упрощённый «сертификат»: просто набор пар «ключ-значение» + подпись
struct SimpleCert {
    std::map<std::string, std::string> fields; // CN, O, validity, serial и т. д.
    std::string signature; // Подпись УЦ в виде строки с числом

    // Конструктор по умолчанию: пустой сертификат
    SimpleCert() = default;

    // Конструктор с инициализацией полей и подписи
    SimpleCert(const std::map<std::string, std::string>& init_fields,
        const std::string& init_signature)
        : fields(init_fields), signature(init_signature) {
    }

    // Конструктор только с полями (подпись пустая)
    explicit SimpleCert(const std::map<std::string, std::string>& init_fields)
        : fields(init_fields) {
    }

    // Конструктор копирования
    SimpleCert(const SimpleCert& other)
        : fields(other.fields), signature(other.signature) {
    }

    // Оператор присваивания
    SimpleCert& operator=(const SimpleCert& other) {
        if (this != &other) {
            fields = other.fields;
            signature = other.signature;
        }
        return *this;
    }
};

struct CSR {
    std::map<std::string, std::string> subject; // Данные владельца: CN=example.com и т. п.
    std::string pubkey_n; // Открытый модуль n клиента
    std::string pubkey_e; // Открытый показатель e клиента

    // Конструктор по умолчанию: пустой CSR
    CSR() = default;

    // Конструктор с полной инициализацией
    CSR(const std::map<std::string, std::string>& init_subject,
        const std::string& init_pubkey_n,
        const std::string& init_pubkey_e)
        : subject(init_subject), pubkey_n(init_pubkey_n), pubkey_e(init_pubkey_e) {
    }

    // Конструктор только с субъектом (ключи пустые)
    explicit CSR(const std::map<std::string, std::string>& init_subject)
        : subject(init_subject) {
    }

    // Конструктор копирования
    CSR(const CSR& other)
        : subject(other.subject), pubkey_n(other.pubkey_n), pubkey_e(other.pubkey_e) {
    }

    // Оператор присваивания
    CSR& operator=(const CSR& other) {
        if (this != &other) {
            subject = other.subject;
            pubkey_n = other.pubkey_n;
            pubkey_e = other.pubkey_e;
        }
        return *this;
    }
};

 
// Модульное умножение с защитой от переполнения: (a * b) mod m
sing_value_type mod_mul(sing_value_type a, sing_value_type b, sing_value_type m) {
    sing_value_type res = 0;
    a %= m;
    while (b > 0) {
        if (b & 1) res = (res + a) % m;
        a = (a << 1) % m;
        b >>= 1;
    }
    return res;
}

// mod_inv для sing_value_type через расширенный Евклид (упрощённо)
sing_value_type mod_inv(sing_value_type e, sing_value_type mod) {
    sing_value_type t = 0, newt = 1;
    sing_value_type r = mod, newr = e;

    while (newr != zero) {
        sing_value_type q = r / newr;
        // r, newr = newr, r - q*newr
        sing_value_type tmp = r - q * newr; r = newr; newr = tmp;
        // t, newt = newt, t - q*newt
        sing_value_type tmp2 = t - q * newt; t = newt; newt = tmp2;
    }
    if (r > 1) return 0; // обратного нет
    if (t < 0) t += mod; // в этой библиотеке нет знаковых, так что это скорее концептуально
    return t;
}

sing_value_type mod_exp(sing_value_type base, sing_value_type exp, sing_value_type mod) {
    sing_value_type result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

// Расширенный алгоритм Евклида: возвращает gcd(a,b) и находит x,y: a*x + b*y = gcd
sing_value_type ext_gcd(sing_value_type a, sing_value_type b, sing_value_type& x, sing_value_type& y) {
    if (b == zero) {
        x = 1; y = 0;
        return a;
    }
    sing_value_type x1, y1;
    sing_value_type gcd = ext_gcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return gcd;
}

const sing_value_type two(2);


// n > 1, n нечётное
bool miller_rabin_pass(const sing_value_type& n, const sing_value_type& a,
    const sing_value_type& d, int s) {
    // x = a^d mod n (используй свой mod_exp)
    sing_value_type x = mod_exp(a, d, n);

    if (x == 1 || x == n - 1) return true;

    for (int r = 1; r < s; ++r) {
        x = mod_mul(x, x, n); // x = x^2 mod n
        if (x == n - 1) return true;
        // Если x стало 1 раньше, чем мы увидели n-1 — это «разрыв баланса» (составное)
        if (x == 1) return false;
    }
    return false; // не прошло
}



// === УЯЗВИМЫЙ ГПСЧ: слаб в первые 10 секунд ===
class VulnerableRNG {
    static std::random_device* rd;  // источник энтропии (если доступен)
    static std::mt19937* gen; // генератор Мерсенна-Твистера
public:
    static bool is_weak_window; // true в первые 10 сек
    static void seed() {
    }
    static sing_value_type  rand_int(sing_value_type  low, sing_value_type  high) {
  
        if (rd == nullptr)
        {
            rd = new std::random_device();
            gen = new std::mt19937((*rd)());
        }
        std::uniform_int_distribution<unsigned long long> dist(low, high);
        return sing_value_type(dist(*gen));
    }
};
std::random_device* VulnerableRNG::rd;
std::mt19937* VulnerableRNG::gen;

bool VulnerableRNG::is_weak_window = true;


bool is_prime(const sing_value_type& n, int k = 8) {
    static const sing_value_type two = 2;
    static const sing_value_type three = 3;
    static const sing_value_type zero = 0;

    if (n < two) return false;
    if (n == two || n == three) return true;
    if (n % two == zero) return false;

    // Представим n-1 = d * 2^s, d нечётное
    sing_value_type d = n - 1;
    int s = 0;
    while (d % two == zero) {
        d = d / two;
        ++s;
    }

    // Для маленьких n можно ещё добавить быстрый детерминированный фильтр
    // (проверить на маленькие простые до 100–1000), чтобы отсечь мусор раньше

    // k раундов со случайными a
    for (int i = 0; i < k; ++i) {
        // Тут нужен ГСЧ для bigint; у тебя уже есть свой ГСЧ на C++
        sing_value_type a = VulnerableRNG::rand_int(two, n - two);
        if (!miller_rabin_pass(n, a, d, s))
            return false;
    }
    return true;
}

// Генерация простого числа с использованием уязвимого ГПСЧ
sing_value_type  gen_prime_vuln(sing_value_type  low, sing_value_type  high) {
    sing_value_type  p;
    do {
        p = VulnerableRNG::rand_int(low, high);
    } while (!is_prime(p));
    return p;
}

// Упрощённый хеш для демонстрации
sing_value_type simple_hash(const std::string& str, sing_value_type mod) {
    sing_value_type h = 0;
    for (char c : str) {
        h = (h * 31 + (unsigned char)c) % mod;
    }
    return h;
}



// Создаём самоподписанный сертификат УЦ
SimpleCert generate_root_ca(sing_value_type ca_n, sing_value_type ca_e, sing_value_type ca_d) {
    SimpleCert ca_cert;
    ca_cert.fields["CN"] = "My Mini CA";
    ca_cert.fields["validity_start"] = "2024-01-01";
    ca_cert.fields["validity_end"] = "2034-01-01";
    ca_cert.fields["serial"] = "1"; // Серийный номер
    ca_cert.fields["pubkey_n"] = to_string(ca_n);
    ca_cert.fields["pubkey_e"] = to_string(ca_e);

    // «Подписываем» сертификат: хешируем поля и подписываем RSA
    std::string data_to_sign;
    for (const auto& field : ca_cert.fields) {
        data_to_sign += field.first + ":" + field.second + "|";
    }
    sing_value_type hash_val = simple_hash(data_to_sign, ca_n); // Ваш хеш-метод
    sing_value_type sig = mod_exp(hash_val, ca_d, ca_n); // Подпись: hash^d mod n
    ca_cert.signature = to_string(sig);

    return ca_cert;
}

// Формирование CSR клиентом
CSR create_csr(const std::map<std::string, std::string>& subject,
    sing_value_type client_n, sing_value_type client_e) {
    CSR csr;
    csr.subject = subject;
    csr.pubkey_n = to_string(client_n);
    csr.pubkey_e = to_string(client_e);
    return csr;
}

// Подписание CSR УЦ
SimpleCert sign_csr(const CSR& csr, const SimpleCert& ca_cert,
    sing_value_type ca_d, sing_value_type ca_n) {
    SimpleCert client_cert;

    // Копируем данные из CSR
    for (const auto& field : csr.subject) {
        client_cert.fields[field.first] = field.second;
    }

    // Добавляем атрибуты от УЦ
    client_cert.fields["issuer"] = ca_cert.fields.at("CN");
    client_cert.fields["validity_start"] = "2024-01-01";
    client_cert.fields["validity_end"] = "2025-01-01";
    client_cert.fields["serial"] = std::to_string(rand() % 100000 + 1); // Случайный серийный номер
    client_cert.fields["pubkey_n"] = csr.pubkey_n;
    client_cert.fields["pubkey_e"] = csr.pubkey_e;

    // Подписываем сертификат клиента закрытым ключом УЦ
    std::string data_to_sign;
    for (const auto& field : client_cert.fields) {
        data_to_sign += field.first + ":" + field.second + "|";
    }
    sing_value_type hash_val = simple_hash(data_to_sign, ca_n);
    sing_value_type sig = mod_exp(hash_val, ca_d, ca_n);
    client_cert.signature = to_string(sig);

    return client_cert;
}

// Проверка сертификата
bool verify_cert(const SimpleCert& cert, const SimpleCert& ca_cert) {
    // Берём открытый ключ УЦ из его сертификата
    sing_value_type ca_pub_n = sing_value_type(ca_cert.fields.at("pubkey_n"), 10);
    sing_value_type ca_pub_e = sing_value_type(ca_cert.fields.at("pubkey_e"), 10);

    // Восстанавливаем хеш из подписи сертификата
    sing_value_type sig_val = sing_value_type(cert.signature, 10);
    sing_value_type recovered_hash = mod_exp(sig_val, ca_pub_e, ca_pub_n);

    // Считаем хеш от полей сертификата
    std::string data_to_hash;
    for (const auto& field : cert.fields) {
        data_to_hash += field.first + ":" + field.second + "|";
    }
    sing_value_type actual_hash = simple_hash(data_to_hash, ca_pub_n);

    return recovered_hash == actual_hash;
}

int attempts = 0;
// === АТАКУЮЩИЙ МОДУЛЬ: перебирает семена и восстанавливает ключи ===
class Attacker {
public:
    bool safe_mul(sing_value_type a, sing_value_type b, sing_value_type& result) {
        if (a == zero || b == zero) {
            result = 0;
            return true;
        }
        result = a * b;
        return (result / a == b); // если при делении обратно не получили b — было переполнение
    }

    // Перебираем семена в предполагаемом временном окне (±30 сек от T)
    bool crack_rsa_key(sing_value_type n, sing_value_type e, std::wostream& log, sing_value_type& _p,sing_value_type& _q) {
        auto start = std::chrono::steady_clock::now();
        auto end = start + std::chrono::seconds(1); // Лимит времени — 3 секунды
        attempts = 1;
        sing_value_type sqrt_n = static_cast<sing_value_type>(isqrt(n)) + 1;

        log << L"Запуск атаки на RSA ключ (n=" << string_to_wstring(to_string(n)) << L", e=" << string_to_wstring(to_string(e)) << L")\n";
        log << L"Ограничение по времени: 1 секунды\n";
        sing_value_type mina(min_prime);
        while (std::chrono::steady_clock::now() < end) {
            // Генерируем p в диапазоне [2, sqrt(n)]
            sing_value_type p_candidate = gen_prime_trial(mina, sqrt_n);

            _p = p_candidate;
            // Проверяем, делится ли n на p_candidate
            if (n % p_candidate == zero) {
                sing_value_type q_candidate = n / p_candidate;
                MessageBeep(MB_ICONASTERISK);
                MessageBeep(MB_ICONASTERISK);
                MessageBeep(MB_ICONASTERISK);
                // Проверяем, что q тоже простое
                if (is_prime(q_candidate)) {
                    log << L"ВЗЛОМ УСПЕШЕН! Найдено p=" << string_to_wstring(to_string(p_candidate))
                        << L", q=" << string_to_wstring(to_string(q_candidate))  << L"\n";
                    _q = q_candidate;
                    // Безопасное вычисление φ(n)
                    sing_value_type phi_p = p_candidate - 1;
                    sing_value_type phi_q = q_candidate - 1;
                    sing_value_type phi;
                    if (!safe_mul(phi_p, phi_q, phi)) {
                        log << L"Ошибка: переполнение при вычислении φ(n)\n";
                        _q = (sing_value_type) - 1;
                        continue;
                    }

                    // Находим d = e⁻¹ mod φ(n)
                    sing_value_type d_cracked = mod_inv(static_cast<sing_value_type>(e), static_cast<sing_value_type>(phi));
                    if (d_cracked != sing_value_type(-1)) {
                        log << L"Восстановлен закрытый ключ d=" << string_to_wstring(to_string(d_cracked)) << L"\n";
                        return true;
                    }
                    else {
                        log << L"Ошибка: не удалось вычислить обратный элемент\n";
                        _q = (sing_value_type) - 2;
                        continue;
                    }
                }
            }

            attempts++;
            if (attempts % 1000 == 0) { // Логируем прогресс каждые 1000 попыток
                log << L"Попыток: " << attempts << L"\n";
            }
        }

        log << L"Атака не удалась — ключ не взломан за 3 секунды. Всего попыток: "
            << attempts << L"\n";
        return false;
    }

private:
    // Вспомогательная функция для генерации простых при переборе
    sing_value_type gen_prime_trial(sing_value_type low, sing_value_type high) {
        sing_value_type p;
        do {
            p = VulnerableRNG::rand_int(low, high); // Используем текущий rand()
        } while (!is_prime(p));
        return p;
    }
};


sing_value_type ca_p = 0;
sing_value_type  ca_q = 0;


sing_value_type  client_p = 0;
sing_value_type  client_q = 0;



BEGIN_MESSAGE_MAP(CSensorMonitorDlg, CDialogEx)
    ON_BN_CLICKED(IDC_START, &CSensorMonitorDlg::OnBnClickedStart)
    ON_BN_CLICKED(IDC_STOP, &CSensorMonitorDlg::OnBnClickedStop)
    ON_BN_CLICKED(IDC_RESET, &CSensorMonitorDlg::OnBnClickedReset)
    ON_BN_CLICKED(IDC_START_SYNC, &CSensorMonitorDlg::OnBnClickedStartSync)
    ON_BN_CLICKED(IDC_STOP_SYNC, &CSensorMonitorDlg::OnBnClickedStopSync)
    ON_WM_TIMER()
    ON_WM_CTLCOLOR()
    ON_LBN_SELCHANGE(IDC_LIST1, &CSensorMonitorDlg::SelChange)
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
    m_angle = 0.0;
    m_angle_start = 0;
    m_controlSystem = new ControlSystem(this);
    m_lock = false;
    m_rand_prime_error = 0;
    m_rand_circles = 0;
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
    DDX_Control(pDX, IDC_TIMESTAMP2, m_ctrlTimestamp);
    DDX_Control(pDX, IDC_LIST1, m_ctrlList);
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
    m_nTimerID = SetTimer(1, 1000, nullptr);
}

void CSensorMonitorDlg::OnBnClickedStartSync()
{
    m_thread = std::thread(&CSensorMonitorDlg::spasiboEva, this);
}

void CSensorMonitorDlg::OnBnClickedStopSync()
{
    if (m_thread.joinable()) 
    {
        TerminateThread(m_thread.native_handle(), 0);
        m_thread.detach();
    }
}

void CSensorMonitorDlg::spasiboEva()
{
    m_controlSystem->addActuator(new EntropyEaterRNG());
    m_controlSystem->addActuator(new EntropyEaterRNG());
    m_controlSystem->addActuator(new EntropyEaterRNG());
    m_controlSystem->addActuator(new EntropyEaterRNG());
    m_controlSystem->addActuator(new EntropyEaterRNG());
    m_controlSystem->addActuator(new EntropyEaterRNG());
    m_controlSystem->addActuator(new EntropyEaterRNG());
    m_controlSystem->addActuator(new EntropyEaterRNG());
    m_controlSystem->addActuator(new EntropyEaterRNG());
    m_controlSystem->addActuator(new EntropyEaterRNG());
    m_controlSystem->addActuator(new EntropyEaterRNG());
    m_controlSystem->adaptiveSimultaneousControl();
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
    float value = std::stod(dataBufferStr.GetBuffer());
    CTime now = CTime::GetCurrentTime();

    if (m_lock == false)
    {
        ca_p = gen_prime_vuln(min_prime, max_prime);
        ca_q = gen_prime_vuln(min_prime, max_prime);
         
        SetDlgItemText(IDC_PROOT, string_to_wstring(to_string(ca_p)).c_str());
        SetDlgItemText(IDC_QROOT, string_to_wstring(to_string(ca_q)).c_str());

        client_p = gen_prime_vuln(min_prime, max_prime);
        client_q = gen_prime_vuln(min_prime, max_prime);
        m_start_point = new Vector3(value);
        m_lock = true;
    }

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

double CSensorMonitorDlg::read()
{
    return m_angle;
}

void CSensorMonitorDlg::SelChange()
{
    int nSel = m_ctrlList.GetCurSel();
    if (nSel != LB_ERR)
    {
        CString strItem;
        CString* data = (CString*)m_ctrlList.GetItemData(nSel);
        SetDlgItemText(IDC_LOG, *data);
    }
}


void CSensorMonitorDlg::ClearOldData()
{
    CTime cutoff = CTime::GetCurrentTime() - CTimeSpan(0, 0, 3, 0); // 3 минуты назад

    while (!m_dataBuffer.empty() && m_dataBuffer.begin()->timestamp < cutoff)
    {
        m_dataBuffer.erase(m_dataBuffer.begin());
    }
}

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
    double stable = 0;
    if (m_dataBuffer.size() > 2)
    {
        Vector3 a(m_dataBuffer[m_dataBuffer.size() - 1].value);
        Vector3 b(m_dataBuffer[m_dataBuffer.size() - 2].value);
        m_angle = angle_between(a, b);
        stable = angle_between(*m_start_point, a);
        if (m_angle > 0.001 || stable < 0.0000001)
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
    m_angle_start = stable;
    m_prev_value = m_dataBuffer[m_dataBuffer.size() - 1].value;
    m_ctrlCondition.SetWindowText(conditionStr);
    // Для изменения цвета текста потребуется дополнительный обработчик WM_CTLCOLOR
            // Обновление временной метки
    CString timestamp;
    timestamp.Format(L"Обновлено: %02d:%02d:%02d | Точек данных: %d  %lf    %lf %ld",
        CTime::GetCurrentTime().GetHour(),
        CTime::GetCurrentTime().GetMinute(),
        CTime::GetCurrentTime().GetSecond(),
        m_dataBuffer.size(), m_angle, stable, attempts);
    m_ctrlTimestamp.SetWindowText(timestamp);

}

#include <sstream>

const sing_value_type one(1);

int is = 0;
void CSensorMonitorDlg::check_func()
{
    std::wstringbuf log_buffer;
    std::wostream log_stream(&log_buffer);
    time_t start_time = time(0);
    log_stream << _T("=== СИМУЛЯЦИЯ АТАКИ НА СЛАБЫЙ ГПСЧ ===\n");
    log_stream << _T("M_ANGLE=") << m_angle << _T("\n");
    log_stream << _T("RELATE M_START_ANGLE=") << m_angle_start << _T("\n");
    log_stream << _T("Запуск системы в момент ") << start_time << _T(" (это наша точка отсчёта)\n\n");
    bool add_to_log = false;
      // Включаем уязвимое окно на 5 сек — именно в этот момент будут генерироваться ключи
    VulnerableRNG::is_weak_window = false;
    VulnerableRNG::seed();

    //    log_stream << "--- ГЕНЕРАЦИЯ КЛЮЧЕЙ УЦ В УЯЗВИМЫЙ ПЕРИОД ---\n";
        // Генерируем ключи УЦ в уязвимый период

    sing_value_type ca_n = ca_p * ca_q;
    sing_value_type ca_phi = (sing_value_type)(ca_p - 1) * (ca_q - 1);
    sing_value_type ca_e = 65537;
    while (ext_gcd(ca_e, ca_phi, *(new sing_value_type), *(new sing_value_type)) != one) ca_e += 2;
    sing_value_type ca_d = mod_inv(ca_e, ca_phi);

    SimpleCert ca_cert = generate_root_ca(ca_n, ca_e, ca_d);
    log_stream << _T("УЦ создан в уязвимый период. n=") << string_to_wstring(to_string(ca_n))
    << _T(", p=") << string_to_wstring(to_string(ca_p)) << _T(", q=") << string_to_wstring(to_string(ca_q)) << _T("\n");
    sing_value_type client_n = (sing_value_type)(client_p * client_q);
    sing_value_type client_phi = (sing_value_type)(client_p - 1) * (client_q - 1);
    sing_value_type client_e = 65537;
    sing_value_type client_d = 0;
    
 
    // Клиент генерирует ключи уже в «безопасном» режиме
    log_stream << _T("\n--- ГЕНЕРАЦИЯ КЛЮЧЕЙ КЛИЕНТА В НОРМАЛЬНОМ РЕЖИМЕ ---\n");
    VulnerableRNG::seed(); // «Нормальный» seed


    if (client_e >= client_phi) client_e = 3;
    while (ext_gcd(client_e, client_phi, *(new sing_value_type), *(new sing_value_type)) != one) client_e += 2;
    client_d = mod_inv(client_e, client_phi);

    // Создаём CSR от клиента
    std::map<std::string, std::string> subject;
    subject["CN"] = "client.example.com";
    subject["O"] = "Client Org";

    CSR client_csr = create_csr(subject, client_n, client_e);
    log_stream << "CSR создан!\n";

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
        m_rand_prime_error++;
        SetDlgItemText(IDC_RAND_PRIME_ERROR, string_to_wstring(to_string(m_rand_prime_error)).c_str());
         
        return;
    }

    // === АТАКА НА КЛЮЧ УЦ ===
    log_stream << _T("\n=== ЗАПУСК АТАКИ ") << is++ << _T(" НА КЛЮЧ УЦ ===\n");
    Attacker attacker;
    sing_value_type p = 0;
    sing_value_type q = 0;

    bool attack_success = attacker.crack_rsa_key(ca_n, ca_e, log_stream, p, q );

    SetDlgItemText(IDC_PPRED, string_to_wstring(to_string(p)).c_str());
    SetDlgItemText(IDC_QPRED, string_to_wstring(to_string(q)).c_str());
    if (attack_success) {

        log_stream << _T("min_prime:") << string_to_wstring(to_string(min_prime)).c_str() << "\n";
        log_stream << _T("max_prime:") << string_to_wstring(to_string(max_prime)).c_str() << "\n";
        log_stream << _T("\n=== АТАКА УСПЕШНА: злоумышленник восстановил закрытый ключ УЦ! ===\n");
        log_stream << _T("Теперь он может подписывать любые сертификаты от имени УЦ.\n");
        add_to_log = true;
    }
    else {
        log_stream << _T("\n=== АТАКА НЕ УДАЛАСЬ: ключ УЦ защищён. ===\n");
        min_prime = min_prime + step_prime;
        if (min_prime > max_prime)
        {
            min_prime = min_prime_start;
            m_rand_circles++;
        }

        SetDlgItemText(IDC_RAND_PRIME_START, string_to_wstring(to_string(min_prime)).c_str());
        SetDlgItemText(IDC_RAND_PRIME_END, string_to_wstring(to_string(max_prime)).c_str());
        SetDlgItemText(IDC_RAND_CIRCLES, string_to_wstring(to_string(m_rand_circles)).c_str());
        SetDlgItemText(IDC_RAND_PRIME_STEP, string_to_wstring(to_string(step_prime)).c_str());

        return;
    }
    sing_value_type evil_n = 0;
    sing_value_type evil_e = 0;
    // Демонстрация: что может сделать злоумышленник, если взломал ключ УЦ
    if (attack_success) {

        log_stream << _T("\n--- ДЕМОНСТРАЦИЯ ЗЛОУМЫШЛЕННЫХ ДЕЙСТВИЙ ---\n");
        // Злоумышленник создаёт фальшивый CSR
        std::map<std::string, std::string> evil_subject;
        evil_subject["CN"] = "evil.com";
        evil_subject["O"] = "Evil Corp";

        // Генерирует свои ключи (но это не обязательно — он может использовать любые)
        sing_value_type evil_p = gen_prime_vuln(min_prime, max_prime);
        sing_value_type  evil_q = gen_prime_vuln(min_prime, max_prime);
        evil_n = (sing_value_type)(evil_p * evil_q);
        evil_e = 65537;

        CSR evil_csr = create_csr(evil_subject, evil_n, evil_e);

        // Подписывает фальшивый сертификат СВОИМ (восстановленным) ключом УЦ
        SimpleCert evil_cert = sign_csr(evil_csr, ca_cert, ca_d, ca_n);
        log_stream << _T("Злоумышленник выпустил фальшивый сертификат для evil.com!\n");

        // Попытка проверки — в нашей системе она пройдёт, потому что подпись валидна!
        if (verify_cert(evil_cert, ca_cert)) {
            log_stream << _T("Фальшивый сертификат прошёл проверку! Угроза реальна.\n");
            add_to_log = true;
        }

        //MessageBox(log_buffer.str().c_str(), _T("ВЗЛОМАНО! PRE PRE PRE ROOT!"), MB_ICONERROR);
    }
    // Клиент подписывает сообщение своим закрытым ключом
    std::string message = "Hello, CA! This is a secure message.";
    sing_value_type msg_hash = simple_hash(message, client_n);
    sing_value_type client_signature = mod_exp(msg_hash, client_d, client_n);

    log_stream << _T("\n--- ПРОВЕРКА ПОДПИСИ СООБЩЕНИЯ КЛИЕНТА ---\n");
    log_stream << _T("Сообщение: ") << string_to_wstring(message) << _T("\n");
    log_stream << _T("Подпись клиента: ") << string_to_wstring(to_string(client_signature)) << _T("\n");

    // Берём открытый ключ клиента из его сертификата
    sing_value_type cert_client_n = sing_value_type(client_cert.fields.at("pubkey_n"), 10);
    sing_value_type cert_client_e = sing_value_type(client_cert.fields.at("pubkey_e"),10);

    // Восстанавливаем хеш из подписи
    sing_value_type recovered_hash = mod_exp(client_signature, cert_client_e, cert_client_n);
    // Считаем хеш от оригинального сообщения
    sing_value_type actual_hash = simple_hash(message, cert_client_n);

    log_stream << _T("Восстановленный хеш: ") <<  string_to_wstring(to_string(recovered_hash)) << _T("\n");
    log_stream << _T("Реальный хеш: ") <<  string_to_wstring(to_string(actual_hash)) << _T("\n");

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

        std::string evil_message = "Transfer all funds to account 12345";
        sing_value_type evil_hash = simple_hash(evil_message, evil_n);
        // Подписываем фальшивое сообщение, выдавая его за клиента
        sing_value_type evil_signature = mod_exp(evil_hash, evil_e, evil_n); // Здесь на самом деле нужно использовать d, но для демонстрации

        log_stream << _T("Злоумышленник создал фальшивую подпись для сообщения: ") << string_to_wstring(evil_message) << _T("\n");
        log_stream << _T("Фальшивая подпись: ") << string_to_wstring(to_string(evil_signature)) << _T("\n");

        // Попытка проверки фальшивой подписи (она не пройдёт, потому что используется другой ключ)
        sing_value_type recovered_evil_hash = mod_exp(evil_signature, cert_client_e, cert_client_n);
        sing_value_type actual_evil_hash = simple_hash(evil_message, cert_client_n);

        if (recovered_evil_hash == actual_evil_hash) {
           
                log_stream << _T("Фальшивая подпись прошла проверку! Угроза реализована.\n");


            add_to_log = true;
             
        }
        else {
            log_stream << _T("Фальшивая подпись не прошла проверку. Нужна более тонкая атака.\n");

            // Более изощрённая атака: злоумышленник создаёт сертификат с тем же n, но другим e
            // и использует его для подделки подписи
            std::map<std::string, std::string> tricky_subject;
            tricky_subject[("CN")] = "trusted.com";
            tricky_subject[("O")] = "Trusted Org";

            CSR tricky_csr = create_csr(tricky_subject, cert_client_n, 3); // Используем тот же n, но e=3
            SimpleCert tricky_cert = sign_csr(tricky_csr, ca_cert, ca_d, ca_n);

            // Теперь подпись, созданная с e=3, может быть проверена с использованием сертификата
            sing_value_type tricky_signature = mod_exp(evil_hash, 3, cert_client_n); // Подпись с маленьким e

            sing_value_type recovered_tricky_hash = mod_exp(tricky_signature, 3, cert_client_n);
            if (recovered_tricky_hash == actual_evil_hash) {
                log_stream << _T("Изощрённая подделка подписи прошла проверку! Критическая уязвимость.\n");

           //     m_ctrlList.InsertItem(0, 0, _T("Взлом 4"), 0, 0, 0, (LPARAM)new CString(log_buffer.str().c_str()));
                MessageBox(log_buffer.str().c_str(), _T("ВЗЛОМАНО! ROOT!"), MB_ICONERROR);
            }
            else {
                log_stream << _T("Изощрённая подделка не удалась.\n");

            }
        }
    }
    if (add_to_log)
    {
        m_ctrlList.SetItemData(m_ctrlList.AddString(_T("Взлом +")), (DWORD_PTR)(new CString(log_buffer.str().c_str())));
        MessageBeep(MB_ABORTRETRYIGNORE);
        MessageBeep(MB_ABORTRETRYIGNORE);
        MessageBeep(MB_ABORTRETRYIGNORE);
        MessageBeep(MB_ABORTRETRYIGNORE);
        MessageBeep(MB_ABORTRETRYIGNORE);
        MessageBeep(MB_ABORTRETRYIGNORE);
        UpdateData(0);
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

