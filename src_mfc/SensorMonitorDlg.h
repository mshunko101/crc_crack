#pragma once
#include <afxwin.h>
#include <list>
#include <string>
#include "CManipulator.h"


#include <cmath>
// Структура для хранения вектора (x1, x2, x3)
struct Vector3 {
    double x1, x2, x3;

    // Конструктор
    Vector3(float y) : x1(2.0 * y / 3.0), x2(y / 3.0), x3(y* y) {}

    // Длина вектора
    double length() const {
        return std::sqrt(x1 * x1 + x2 * x2 + x3 * x3);
    }

    // Скалярное произведение с другим вектором
    double dot(const Vector3& other) const {
        return x1 * other.x1 + x2 * other.x2 + x3 * other.x3;
    }


    Vector3(double x1 = 0, double x2 = 0, double x3 = 0) : x1(x1), x2(x2), x3(x3) {}
    Vector3 operator+(const Vector3& o) const { return { x1 + o.x1, x2 + o.x2, x3 + o.x3 }; }
    Vector3 operator-(const Vector3& o) const { return { x1 - o.x1, x2 - o.x2, x3 - o.x3 }; }
    Vector3 operator*(double s) const { return { x1 * s, x2 * s, x3 * s }; }
    double norm2() const { return x1 * x1 + x2 * x2 + x3 * x3; }
    double norm() const { return std::sqrt(norm2()); }
    Vector3 normalize() const {
        double n = norm();
        return (n > 1e-12) ? (*this) * (1.0 / n) : Vector3{};
    }
private:
    // Частный конструктор для разности векторов
    Vector3(int dummy, double dx1, double dx2, double dx3) : x1(dx1), x2(dx2), x3(dx3) {}
};



// Структура для хранения данных с временной меткой
struct SensorData {
    CTime timestamp;
    float value;
}; 
class CSensorMonitorDlg : public CDialogEx, public Sensor
{
public:
    CSensorMonitorDlg(CWnd* pParent = nullptr);

protected:
    virtual void DoDataExchange(CDataExchange* pDX);

    DECLARE_MESSAGE_MAP()
public:
    afx_msg void OnBnClickedStart();
    afx_msg void OnBnClickedReset();
    afx_msg void OnBnClickedStop();
    afx_msg void OnTimer(UINT_PTR nIDEvent);
    afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
    BOOL OnInitDialog() override;
private:
    void StartSerial();
    void StopSerial();
    void ReadSerialData();
    void UpdateMetrics();
    void ClearOldData();
    BOOL SendCommandAndReadResponse(HANDLE hCom, CString& outResponse);
    void OnBnClickedStartSync();
    void OnBnClickedStopSync();
    void spasiboEva();
    void check_func();
    void SelChange();
    double read() override;
    // COM-порт
    HANDLE m_hSerial;
    bool m_bRunning;
    float m_balance_step;
    float m_diffs_step;
    float m_prev_value;
    float m_prev_value_sq;
    std::thread m_thread;
    bool m_lock;
    // Буфер данных за последние 3 минуты
    std::vector<SensorData> m_dataBuffer;

    // Элементы управления для вывода
    CStatic m_ctrlCurrentValue;
    CStatic m_ctrlCurrentDiff;
    CStatic m_ctrlMinDiff;
    CStatic m_ctrlMaxDiff;
    CStatic m_ctrlBalance;
    CStatic m_ctrlMinValue;
    CStatic m_ctrlMaxValue;
    CStatic m_ctrlCondition;
    CStatic m_ctrlTimestamp;
    volatile float m_angle;
    volatile float m_angle_start;
    volatile int m_rand_circles;
    volatile int m_rand_prime_error;
    ControlSystem* m_controlSystem;
    CListBox m_ctrlList;
    // Таймер для обновления интерфейса
    UINT_PTR m_nTimerID;
    Vector3* m_start_point;
};
