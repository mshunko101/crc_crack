#pragma once
#include <afxwin.h>
#include <list>
#include <string>
#include "CManipulator.h"

// Структура для хранения данных с временной меткой
struct SensorData {
    CTime timestamp;
    double value;
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
    double m_balance_step;
    double m_diffs_step;
    double m_prev_value;
    double m_prev_value_sq;
    std::thread m_thread;
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
};
