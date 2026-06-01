
// RandSyncDlg.cpp: файл реализации
//

#include "pch.h"
#include "framework.h"
#include "RandSync.h"
#include "RandSyncDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


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
long long simple_hash(const std::string& str, long long mod) {
    long long h = 0;
    for (char c : str) {
        h = (h * 31 + (unsigned char)c) % mod;
    }
    return h;
}

// Упрощённый «сертификат»: просто набор пар «ключ-значение» + подпись
struct SimpleCert {
    std::map<std::string, std::string> fields; // CN, O, validity, serial и т. д.
    std::string signature; // Подпись УЦ в виде строки с числом
};

struct CSR {
    std::map<std::string, std::string> subject; // Данные владельца: CN=example.com и т. п.
    std::string pubkey_n; // Открытый модуль n клиента
    std::string pubkey_e; // Открытый показатель e клиента
};

// Создаём самоподписанный сертификат УЦ
SimpleCert generate_root_ca(long long ca_n, long long ca_e, long long ca_d) {
    SimpleCert ca_cert;
    ca_cert.fields["CN"] = "My Mini CA";
    ca_cert.fields["validity_start"] = "2024-01-01";
    ca_cert.fields["validity_end"] = "2034-01-01";
    ca_cert.fields["serial"] = "1"; // Серийный номер
    ca_cert.fields["pubkey_n"] = std::to_string(ca_n);
    ca_cert.fields["pubkey_e"] = std::to_string(ca_e);

    // «Подписываем» сертификат: хешируем поля и подписываем RSA
    std::string data_to_sign;
    for (const auto& field : ca_cert.fields) {
        data_to_sign += field.first + ":" + field.second + "|";
    }
    long long hash_val = simple_hash(data_to_sign, ca_n); // Ваш хеш-метод
    long long sig = mod_exp(hash_val, ca_d, ca_n); // Подпись: hash^d mod n
    ca_cert.signature = std::to_string(sig);

    return ca_cert;
}

// Формирование CSR клиентом
CSR create_csr(const std::map<std::string, std::string>& subject,
    long long client_n, long long client_e) {
    CSR csr;
    csr.subject = subject;
    csr.pubkey_n = std::to_string(client_n);
    csr.pubkey_e = std::to_string(client_e);
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
    long long hash_val = simple_hash(data_to_sign, ca_n);
    long long sig = mod_exp(hash_val, ca_d, ca_n);
    client_cert.signature = std::to_string(sig);

    return client_cert;
}

// Проверка сертификата
bool verify_cert(const SimpleCert& cert, const SimpleCert& ca_cert) {
    // Берём открытый ключ УЦ из его сертификата
    long long ca_pub_n = std::stoll(ca_cert.fields.at("pubkey_n"));
    long long ca_pub_e = std::stoll(ca_cert.fields.at("pubkey_e"));

    // Восстанавливаем хеш из подписи сертификата
    long long sig_val = std::stoll(cert.signature);
    long long recovered_hash = mod_exp(sig_val, ca_pub_e, ca_pub_n);

    // Считаем хеш от полей сертификата
    std::string data_to_hash;
    for (const auto& field : cert.fields) {
        data_to_hash += field.first + ":" + field.second + "|";
    }
    long long actual_hash = simple_hash(data_to_hash, ca_pub_n);

    return recovered_hash == actual_hash;
}

// === АТАКУЮЩИЙ МОДУЛЬ: перебирает семена и восстанавливает ключи ===
class Attacker {
public:
    // Перебираем семена в предполагаемом временном окне (±30 сек от T)
    bool crack_rsa_key(long long n, long long e, time_t approx_time) {
        std::cout << "Атака: перебор семян около времени " << approx_time << "\n";
        for (int offset = -30; offset <= 30; ++offset) {
            time_t candidate_seed = approx_time + offset;
            srand(static_cast<unsigned int>(candidate_seed));

            // Пытаемся сгенерировать p и q, которые дадут n
            for (int i = 0; i < 200; ++i) { // 200 попыток на семя
                int p_candidate = gen_prime_trial(100, 200); // Диапазон как у УЦ
                int q_candidate = gen_prime_trial(100, 200);
                long long n_candidate = (long long)p_candidate * q_candidate;

                if (n_candidate == n) {
                    std::cout << "ВЗЛОМ УСПЕШЕН! Найдено p=" << p_candidate
                        << ", q=" << q_candidate << "\n";
                    long long phi = (long long)(p_candidate - 1) * (q_candidate - 1);
                    long long d_cracked = mod_inv(e, phi);
                    std::cout << "Восстановлен закрытый ключ d=" << d_cracked << "\n";
                    return true;
                }
            }
        }
        std::cout << "Атака не удалась — ключ не взломан.\n";
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
 






/*

#include <iostream>
#include <string>
#include <map>
#include <cstdlib>
#include <ctime>

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

// Генерируем случайное простое в диапазоне [low, high]
int gen_prime(int low, int high) {
    int p;
    do {
        p = low + rand() % (high - low + 1);
    } while (!is_prime(p));
    return p;
}

// Упрощённый хеш для демонстрации
long long simple_hash(const std::string& str, long long mod) {
    long long h = 0;
    for (char c : str) {
        h = (h * 31 + (unsigned char)c) % mod;
    }
    return h;
}

// Генерация случайного серийного номера
std::string gen_random_serial() {
    return std::to_string(rand() % 100000 + 1); // Случайное число от 1 до 100000
}

// Упрощённый «сертификат»: просто набор пар «ключ-значение» + подпись
struct SimpleCert {
    std::map<std::string, std::string> fields; // CN, O, validity, serial и т. д.
    std::string signature; // Подпись УЦ в виде строки с числом
};

struct CSR {
    std::map<std::string, std::string> subject; // Данные владельца: CN=example.com и т. п.
    std::string pubkey_n; // Открытый модуль n клиента
    std::string pubkey_e; // Открытый показатель e клиента
};

// Создаём самоподписанный сертификат УЦ
SimpleCert generate_root_ca(long long ca_n, long long ca_e, long long ca_d) {
    SimpleCert ca_cert;
    ca_cert.fields["CN"] = "My Mini CA";
    ca_cert.fields["validity_start"] = "2024-01-01";
    ca_cert.fields["validity_end"] = "2034-01-01";
    ca_cert.fields["serial"] = "1"; // Серийный номер
    ca_cert.fields["pubkey_n"] = std::to_string(ca_n);
    ca_cert.fields["pubkey_e"] = std::to_string(ca_e);

    // «Подписываем» сертификат: хешируем поля и подписываем RSA
    std::string data_to_sign;
    for (const auto& field : ca_cert.fields) {
        data_to_sign += field.first + ":" + field.second + "|";
    }
    long long hash_val = simple_hash(data_to_sign, ca_n); // Ваш хеш-метод
    long long sig = mod_exp(hash_val, ca_d, ca_n); // Подпись: hash^d mod n
    ca_cert.signature = std::to_string(sig);

    return ca_cert;
}

// Формирование CSR клиентом
CSR create_csr(const std::map<std::string, std::string>& subject,
    long long client_n, long long client_e) {
    CSR csr;
    csr.subject = subject;
    csr.pubkey_n = std::to_string(client_n);
    csr.pubkey_e = std::to_string(client_e);
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
    client_cert.fields["issuer"] = ca_cert.fields.at("CN");
    client_cert.fields["validity_start"] = "2024-01-01";
    client_cert.fields["validity_end"] = "2025-01-01";
    client_cert.fields["serial"] = gen_random_serial(); // Случайный серийный номер
    client_cert.fields["pubkey_n"] = csr.pubkey_n;
    client_cert.fields["pubkey_e"] = csr.pubkey_e;

    // Подписываем сертификат клиента закрытым ключом УЦ
    std::string data_to_sign;
    for (const auto& field : client_cert.fields) {
        data_to_sign += field.first + ":" + field.second + "|";
    }
    long long hash_val = simple_hash(data_to_sign, ca_n);
    long long sig = mod_exp(hash_val, ca_d, ca_n);
    client_cert.signature = std::to_string(sig);

    return client_cert;
}

// Проверка сертификата
bool verify_cert(const SimpleCert& cert, const SimpleCert& ca_cert) {
    // Берём открытый ключ УЦ из его сертификата
    long long ca_pub_n = std::stoll(ca_cert.fields.at("pubkey_n"));
    long long ca_pub_e = std::stoll(ca_cert.fields.at("pubkey_e"));

    // Восстанавливаем хеш из подписи сертификата
    long long sig_val = std::stoll(cert.signature);
    long long recovered_hash = mod_exp(sig_val, ca_pub_e, ca_pub_n);

    // Считаем хеш от полей сертификата
    std::string data_to_hash;
    for (const auto& field : cert.fields) {
        data_to_hash += field.first + ":" + field.second + "|";
    }
    long long actual_hash = simple_hash(data_to_hash, ca_pub_n);

    return recovered_hash == actual_hash;
}

int main() {
    srand(time(0));

    // Шаг 1: Генерация УЦ
    int ca_p = gen_prime(100, 200);
    int ca_q = gen_prime(100, 200);
    long long ca_n = (long long)ca_p * ca_q;
    long long ca_phi = (long long)(ca_p - 1) * (ca_q - 1);
    long long ca_e = 65537;
    if (ca_e >= ca_phi) ca_e = 3;
    while (ext_gcd(ca_e, ca_phi, *(new long long), *(new long long)) != 1) ca_e += 2;
    long long ca_d = mod_inv(ca_e, ca_phi);

    SimpleCert ca_cert = generate_root_ca(ca_n, ca_e, ca_d);
    std::cout << "CA создан!\n";
    std::cout << "Открытый ключ CA (n): " << ca_n << "\n";
    std::cout << "Открытый ключ CA (e): " << ca_e << "\n\n";

    // Шаг 2: Клиент генерирует ключи и CSR
    int client_p = gen_prime(50, 150);
    int client_q = gen_prime(50, 150);
    long long client_n = (long long)(client_p * client_q);
    long long client_phi = (long long)(client_p - 1) * (client_q - 1);
    long long client_e = 65537;
    if (client_e >= client_phi) client_e = 3;
    while (ext_gcd(client_e, client_phi, *(new long long), *(new long long)) != 1) client_e += 2;
    long long client_d = mod_inv(client_e, client_phi);

    // Создаём CSR от клиента
    std::map<std::string, std::string> subject;
    subject["CN"] = "client.example.com";
    subject["O"] = "Client Org";

    CSR client_csr = create_csr(subject, client_n, client_e);
    std::cout << "CSR создан!\n";

    // Шаг 3: УЦ подписывает CSR и выдаёт сертификат
    SimpleCert client_cert = sign_csr(client_csr, ca_cert, ca_d, ca_n);
    std::cout << "Сертификат клиента выдан!\n";

    // Выводим некоторые поля сертификата клиента
    std::cout << "Issuer: " << client_cert.fields.at("issuer") << "\n";
    std::cout << "Subject CN: " << client_cert.fields.at("CN") << "\n";
    std::cout << "Serial: " << client_cert.fields.at("serial") << "\n\n";

    // Шаг 4: Проверка сертификата клиента с помощью открытого ключа УЦ
    if (verify_cert(client_cert, ca_cert)) {
        std::cout << "Проверка сертификата: ПРОЙДЕНА! Сертификат доверен.\n";
    }
    else {
        std::cout << "Проверка сертификата: НЕ ПРОЙДЕНА!\n";
        return 1;
    }

    // Шаг 5: Клиент подписывает сообщение своим закрытым ключом
    std::string message = "Hello, CA! This is a secure message.";
    // Считаем хеш сообщения
    long long msg_hash = simple_hash(message, client_n);
    // Подписываем хеш своим закрытым ключом
    long long client_signature = mod_exp(msg_hash, client_d, client_n);

    std::cout << "Сообщение: " << message << "\n";
    std::cout << "Хеш сообщения: " << msg_hash << "\n";
    std::cout << "Подпись клиента: " << client_signature << "\n\n";

    // Шаг 6: УЦ проверяет подпись, используя сертификат клиента
    // Берём открытый ключ клиента из его сертификата
    long long cert_client_n = std::stoll(client_cert.fields.at("pubkey_n"));
    long long cert_client_e = std::stoll(client_cert.fields.at("pubkey_e"));

    // Восстанавливаем хеш из подписи
    long long recovered_hash = mod_exp(client_signature, cert_client_e, cert_client_n);
    // Считаем хеш от оригинального сообщения
    long long actual_hash = simple_hash(message, cert_client_n);

    std::cout << "Восстановленный хеш: " << recovered_hash << "\n";
    std::cout << "Реальный хеш: " << actual_hash << "\n";

    if (recovered_hash == actual_hash) {
        std::cout << "Проверка подписи сообщения: ПРОЙДЕНА! Сообщение не изменено и от доверенного клиента.\n";
    }
    else {
        std::cout << "Проверка подписи сообщения: НЕ ПРОЙДЕНА!\n";
    }

    return 0;
}


*/


// Диалоговое окно CAboutDlg используется для описания сведений о приложении

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Данные диалогового окна
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // поддержка DDX/DDV

// Реализация
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// Диалоговое окно CRandSyncDlg



CRandSyncDlg::CRandSyncDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_RANDSYNC_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	double time_period = _ttof(_T("73.8"));

	m_rng = 0;
	m_prev = 0.0;
	r1 = new RNG(static_cast<unsigned int>(time(nullptr)), time_period);
    is = 0;
}

void CRandSyncDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CRandSyncDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_TIMER()
	ON_WM_QUERYDRAGICON()
	ON_WM_CTLCOLOR()
    ON_BN_CLICKED(IDC_START, &CRandSyncDlg::OnBnClickedButtonStart)
    ON_BN_CLICKED(IDC_STOP, &CRandSyncDlg::OnBnClickedButtonStop)
END_MESSAGE_MAP()


// Обработчики сообщений CRandSyncDlg

BOOL CRandSyncDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Добавление пункта "О программе..." в системное меню.

	// IDM_ABOUTBOX должен быть в пределах системной команды.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Задает значок для этого диалогового окна.  Среда делает это автоматически,
	//  если главное окно приложения не является диалоговым
	SetIcon(m_hIcon, TRUE);			// Крупный значок
	SetIcon(m_hIcon, FALSE);		// Мелкий значок

	// TODO: добавьте дополнительную инициализацию

	return TRUE;  // возврат значения TRUE, если фокус не передан элементу управления
}

void CRandSyncDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// При добавлении кнопки свертывания в диалоговое окно нужно воспользоваться приведенным ниже кодом,
//  чтобы нарисовать значок.  Для приложений MFC, использующих модель документов или представлений,
//  это автоматически выполняется рабочей областью.

void CRandSyncDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // контекст устройства для рисования

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Выравнивание значка по центру клиентского прямоугольника
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Нарисуйте значок
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// Система вызывает эту функцию для получения отображения курсора при перемещении
//  свернутого окна.
HCURSOR CRandSyncDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CRandSyncDlg::OnBnClickedButtonStart()
{
	double time_period = _ttof(_T("73.8"));

	r2 = new RNG(static_cast<unsigned int>(time(nullptr)), time_period);
	m_nTimerID = SetTimer(1, 1, nullptr); // Обновление каждую секунду
    SetWindowText(_T("ЕДЕМ!"));
}

void CRandSyncDlg::OnBnClickedButtonStop()
{
    KillTimer(m_nTimerID);
    SetWindowText(_T("СТОИМ!"));
}

HBRUSH CRandSyncDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialogEx::OnCtlColor(pDC, pWnd, nCtlColor);

	// Если это наш контрол с условием
	if (pWnd->GetDlgCtrlID() == IDC_START)
	{
		CString text;

		if (m_rng == 1)
		{
			pDC->SetTextColor(RGB(255, 152, 0)); // Оранжевый
			CRect rect;
			pWnd->GetClientRect(&rect);
			CBrush b(0, RGB(255, 152, 0));
			pDC->FillRect(rect, &b);
		}
		else if (m_rng > 1)
		{
			pDC->SetTextColor(RGB(76, 175, 80)); // Зелёный
			CRect rect;
			pWnd->GetClientRect(&rect);
			CBrush b(0, RGB(76, 175, 80));
			pDC->FillRect(rect, &b);
		}
	}
	return hbr;
}
int is = 0;
void check_func()
{

    time_t start_time = time(0);
    std::cout << "=== СИМУЛЯЦИЯ АТАКИ НА СЛАБЫЙ ГПСЧ ===\n";
    //  std::cout << "Запуск системы в момент " << start_time << " (это наша точка отсчёта)\n\n";

      // Включаем уязвимое окно на 5 сек — именно в этот момент будут генерироваться ключи
    VulnerableRNG::is_weak_window = false;
    VulnerableRNG::seed();

    //    std::cout << "--- ГЕНЕРАЦИЯ КЛЮЧЕЙ УЦ В УЯЗВИМЫЙ ПЕРИОД ---\n";
        // Генерируем ключи УЦ в уязвимый период
    int ca_p = gen_prime_vuln(100, 200);
    int ca_q = gen_prime_vuln(100, 200);
    long long ca_n = (long long)ca_p * ca_q;
    long long ca_phi = (long long)(ca_p - 1) * (ca_q - 1);
    long long ca_e = 65537;
    while (ext_gcd(ca_e, ca_phi, *(new long long), *(new long long)) != 1) ca_e += 2;
    long long ca_d = mod_inv(ca_e, ca_phi);

    SimpleCert ca_cert = generate_root_ca(ca_n, ca_e, ca_d);
    //  std::cout << "УЦ создан в уязвимый период. n=" << ca_n
    //      << ", p=" << ca_p << ", q=" << ca_q << "\n";

      // Через 5 сек выключаем уязвимость — дальше система работает нормально
    std::this_thread::sleep_for(std::chrono::seconds(5));
    VulnerableRNG::is_weak_window = false;

    // Клиент генерирует ключи уже в «безопасном» режиме
 //   std::cout << "\n--- ГЕНЕРАЦИЯ КЛЮЧЕЙ КЛИЕНТА В НОРМАЛЬНОМ РЕЖИМЕ ---\n";
    VulnerableRNG::seed(); // «Нормальный» seed
    int client_p = gen_prime_vuln(50, 150);
    int client_q = gen_prime_vuln(50, 150);
    long long client_n = (long long)(client_p * client_q);
    long long client_phi = (long long)(client_p - 1) * (client_q - 1);
    long long client_e = 65537;
    if (client_e >= client_phi) client_e = 3;
    while (ext_gcd(client_e, client_phi, *(new long long), *(new long long)) != 1) client_e += 2;
    long long client_d = mod_inv(client_e, client_phi);

    // Создаём CSR от клиента
    std::map<std::string, std::string> subject;
    subject["CN"] = "client.example.com";
    subject["O"] = "Client Org";

    CSR client_csr = create_csr(subject, client_n, client_e);
    //   std::cout << "CSR создан!\n";

       // УЦ подписывает CSR и выдаёт сертификат
    SimpleCert client_cert = sign_csr(client_csr, ca_cert, ca_d, ca_n);
    //   std::cout << "Сертификат клиента выдан!\n";

       // Проверка сертификата клиента с помощью открытого ключа УЦ
    if (verify_cert(client_cert, ca_cert)) {
        //       std::cout << "Проверка сертификата: ПРОЙДЕНА! Сертификат доверен.\n";
    }
    else {
        //   std::cout << "Проверка сертификата: НЕ ПРОЙДЕНА!\n";
        return;
    }

    // === АТАКА НА КЛЮЧ УЦ ===
    std::cout << "\n=== ЗАПУСК АТАКИ " << is++ << " НА КЛЮЧ УЦ ===\n";
    Attacker attacker;
    bool attack_success = attacker.crack_rsa_key(ca_n, ca_e, start_time);

    if (attack_success) {
        std::cout << "\n=== АТАКА УСПЕШНА: злоумышленник восстановил закрытый ключ УЦ! ===\n";
        std::cout << "Теперь он может подписывать любые сертификаты от имени УЦ.\n";
    }
    else {
        //    std::cout << "\n=== АТАКА НЕ УДАЛАСЬ: ключ УЦ защищён. ===\n";
        return;
    }
    long long evil_n = 0;
    long long evil_e = 0;
    // Демонстрация: что может сделать злоумышленник, если взломал ключ УЦ
    if (attack_success) {
        std::cout << "\n--- ДЕМОНСТРАЦИЯ ЗЛОУМЫШЛЕННЫХ ДЕЙСТВИЙ ---\n";
        // Злоумышленник создаёт фальшивый CSR
        std::map<std::string, std::string> evil_subject;
        evil_subject["CN"] = "evil.com";
        evil_subject["O"] = "Evil Corp";

        // Генерирует свои ключи (но это не обязательно — он может использовать любые)
        int evil_p = gen_prime_vuln(30, 80);
        int evil_q = gen_prime_vuln(30, 80);
        evil_n = (long long)(evil_p * evil_q);
        evil_e = 65537;

        CSR evil_csr = create_csr(evil_subject, evil_n, evil_e);

        // Подписывает фальшивый сертификат СВОИМ (восстановленным) ключом УЦ
        SimpleCert evil_cert = sign_csr(evil_csr, ca_cert, ca_d, ca_n);
        std::cout << "Злоумышленник выпустил фальшивый сертификат для evil.com!\n";

        // Попытка проверки — в нашей системе она пройдёт, потому что подпись валидна!
        if (verify_cert(evil_cert, ca_cert)) {
            std::cout << "Фальшивый сертификат прошёл проверку! Угроза реальна.\n";
        }
    }
    // Клиент подписывает сообщение своим закрытым ключом
    std::string message = "Hello, CA! This is a secure message.";
    long long msg_hash = simple_hash(message, client_n);
    long long client_signature = mod_exp(msg_hash, client_d, client_n);

    std::cout << "\n--- ПРОВЕРКА ПОДПИСИ СООБЩЕНИЯ КЛИЕНТА ---\n";
    std::cout << "Сообщение: " << message << "\n";
    std::cout << "Подпись клиента: " << client_signature << "\n";

    // Берём открытый ключ клиента из его сертификата
    long long cert_client_n = std::stoll(client_cert.fields.at("pubkey_n"));
    long long cert_client_e = std::stoll(client_cert.fields.at("pubkey_e"));

    // Восстанавливаем хеш из подписи
    long long recovered_hash = mod_exp(client_signature, cert_client_e, cert_client_n);
    // Считаем хеш от оригинального сообщения
    long long actual_hash = simple_hash(message, cert_client_n);

    std::cout << "Восстановленный хеш: " << recovered_hash << "\n";
    std::cout << "Реальный хеш: " << actual_hash << "\n";

    if (recovered_hash == actual_hash) {
        std::cout << "Проверка подписи сообщения: ПРОЙДЕНА! Сообщение не изменено и от доверенного клиента.\n";
    }
    else {
        std::cout << "Проверка подписи сообщения: НЕ ПРОЙДЕНА!\n";
    }

    // Демонстрация атаки, если злоумышленник взломал ключ УЦ
    if (attack_success) {
        std::cout << "\n--- АТАКА НА ПОДПИСЬ СООБЩЕНИЯ ---\n";
        // Злоумышленник может подделать подпись от имени клиента
        // Он использует свой ключ (или взломанный ключ УЦ) для создания фальшивой подписи

        std::string evil_message = "Transfer all funds to account 12345";
        long long evil_hash = simple_hash(evil_message, evil_n);
        // Подписываем фальшивое сообщение, выдавая его за клиента
        long long evil_signature = mod_exp(evil_hash, evil_e, evil_n); // Здесь на самом деле нужно использовать d, но для демонстрации

        std::cout << "Злоумышленник создал фальшивую подпись для сообщения: " << evil_message << "\n";
        std::cout << "Фальшивая подпись: " << evil_signature << "\n";

        // Попытка проверки фальшивой подписи (она не пройдёт, потому что используется другой ключ)
        long long recovered_evil_hash = mod_exp(evil_signature, cert_client_e, cert_client_n);
        long long actual_evil_hash = simple_hash(evil_message, cert_client_n);

        if (recovered_evil_hash == actual_evil_hash) {
            std::cout << "Фальшивая подпись прошла проверку! Угроза реализована.\n";
        }
        else {
            std::cout << "Фальшивая подпись не прошла проверку. Нужна более тонкая атака.\n";

            // Более изощрённая атака: злоумышленник создаёт сертификат с тем же n, но другим e
            // и использует его для подделки подписи
            std::map<std::string, std::string> tricky_subject;
            tricky_subject["CN"] = "trusted.com";
            tricky_subject["O"] = "Trusted Org";

            CSR tricky_csr = create_csr(tricky_subject, cert_client_n, 3); // Используем тот же n, но e=3
            SimpleCert tricky_cert = sign_csr(tricky_csr, ca_cert, ca_d, ca_n);

            // Теперь подпись, созданная с e=3, может быть проверена с использованием сертификата
            long long tricky_signature = mod_exp(evil_hash, 3, cert_client_n); // Подпись с маленьким e

            long long recovered_tricky_hash = mod_exp(tricky_signature, 3, cert_client_n);
            if (recovered_tricky_hash == actual_evil_hash) {
                std::cout << "Изощрённая подделка подписи прошла проверку! Критическая уязвимость.\n";
                MessageBox(0, _T("КАПЕЦ!"), _T("ВЗЛОМАНО!"), MB_ICONERROR);
            }
            else {
                std::cout << "Изощрённая подделка не удалась.\n";

            }
        }
    }
}


void CRandSyncDlg::OnTimer(UINT_PTR nIDEvent)
{
	if (nIDEvent == 1)
	{
		double l = r2->generate(32);
		double r = abs(r1->generate(32) - l);
		double x3 = l * l;

		if (r <= 0.00001)
		{
			MessageBeep(MB_ICONEXCLAMATION);
			MessageBeep(MB_ICONEXCLAMATION);
			MessageBeep(MB_ICONEXCLAMATION);
            check_func();
			m_rng = 3;
		}
		else
		if (r <= 0.0001)
		{
			MessageBeep(MB_ICONEXCLAMATION);
			MessageBeep(MB_ICONEXCLAMATION);
            check_func();
			m_rng = 2;
		}
		if (r <= 0.001)
		{
			double y = l*l;
			if (m_prev < y)
			{
				MessageBeep(MB_ICONEXCLAMATION);
			}
			else
			{
				m_prev = 0.0;
			}
            check_func();
		}
		m_prev = x3;

	}
	CDialogEx::OnTimer(nIDEvent);
}