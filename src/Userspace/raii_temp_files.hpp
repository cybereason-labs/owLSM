#pragma once

#include <string>
#include <fstream>

namespace owlsm
{

class RaiiTempFile
{
public:
    explicit RaiiTempFile(const std::string& path);
    RaiiTempFile();
    ~RaiiTempFile();

    RaiiTempFile(const RaiiTempFile&) = delete;
    RaiiTempFile& operator=(const RaiiTempFile&) = delete;
    RaiiTempFile(RaiiTempFile&&) = delete;
    RaiiTempFile& operator=(RaiiTempFile&&) = delete;

    template<typename T>
    RaiiTempFile& operator<<(const T& data)
    {
        if (!m_stream.is_open())
        {
            m_stream.open(m_path, std::ios::app);
        }
        m_stream << data;
        m_stream.flush();
        return *this;
    }

    const std::string& getPath() const { return m_path; }

private:
    void setPermissions();
    std::string generateRandomPath() const;
    
    std::string m_path;
    mutable std::ofstream m_stream;
};

}

