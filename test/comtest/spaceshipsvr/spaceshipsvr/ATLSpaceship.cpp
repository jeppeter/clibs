// ATLSpaceship.cpp: CATLSpaceship 的实现

#include "pch.h"
#include "ATLSpaceship.h"


// CATLSpaceship



STDMETHODIMP CATLSpaceship::CallStartFleet(float fStarDate, BSTR* pbstrRecipient)
{
    // TODO: 在此处添加实现代码
    ATLTRACE("Call Start Fleet");
    return S_OK;
}


STDMETHODIMP CATLSpaceship::Fly()
{
    // TODO: 在此处添加实现代码
    OutputDebugStringA("Entering CSpaceship::XMotion::Fly\n");
    ATLTRACE("m_nPosition = %d\n", m_nPosition);
    ATLTRACE("m_nAcceleration = %d\n", m_nAcceleration);
    return S_OK;
}


STDMETHODIMP CATLSpaceship::GetPosition(long* nPosition)
{
    // TODO: 在此处添加实现代码
    ATLTRACE("CATLSpaceShip::GetPosition\n");
    ATLTRACE("m_nPosition = %d\n", m_nPosition);
    ATLTRACE("m_nAcceleration = %d\n", m_nAcceleration);
    *nPosition = m_nPosition;
    return S_OK;
}


STDMETHODIMP CATLSpaceship::Display()
{
    // TODO: 在此处添加实现代码
    // not doing too much here-- we're really just interested in the structure
    ATLTRACE("CSpaceship::XVisual::Display\n");
    ATLTRACE("m_nPosition = %d\n", m_nPosition);
    ATLTRACE("m_nColor = %d\n", m_nColor);
    return S_OK;
}
