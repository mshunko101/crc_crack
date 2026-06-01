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



// Структура для хранения данных с временной меткой
struct SensorData {
    CTime timestamp;
    double value;
};
struct Vector3;
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
    double m_balance_step;
    double m_diffs_step;
    double m_prev_value;
    double m_prev_value_sq;
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
    volatile double m_angle;
    ControlSystem* m_controlSystem;
    CListBox m_ctrlList;
    // Таймер для обновления интерфейса
    UINT_PTR m_nTimerID;
    Vector3* m_start_point;
};
