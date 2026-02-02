#include "raii_temp_files.hpp"
#include "logger.hpp"

#include <filesystem>
#include <random>
#include <sys/stat.h>

namespace owlsm
{

RaiiTempFile::RaiiTempFile(const std::string& path)
    : m_path(path)
{
    std::ofstream file(m_path);
    file.close();
    setPermissions();
    LOG_DEBUG("Created temporary file: " << m_path);
}

RaiiTempFile::RaiiTempFile() : RaiiTempFile(generateRandomPath()) {}

RaiiTempFile::~RaiiTempFile()
{
    if (m_stream.is_open())
    {
        m_stream.close();
    }
    
    std::error_code ec;
    if (std::filesystem::exists(m_path, ec))
    {
        std::filesystem::remove(m_path, ec);
        if (!ec)
        {
            LOG_DEBUG("Deleted temporary file: " << m_path);
        }
        else
        {
            LOG_DEBUG("Failed to delete temporary file: '" << m_path << "' - " << ec.message());
        }
    }
    else
    {
        LOG_DEBUG("Temporary file already deleted: " << m_path);
    }
}

void RaiiTempFile::setPermissions()
{
    if (chmod(m_path.c_str(), S_IRWXU) != 0)
    {
        LOG_DEBUG("Failed to set permissions for temporary file: " << m_path);
    }
}

std::string RaiiTempFile::generateRandomPath() const
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    const char* hex_chars = "0123456789abcdef";
    std::string random_name = "owlsm_temp_";
    
    for (int i = 0; i < 16; ++i)
    {
        random_name += hex_chars[dis(gen)];
    }
    
    return "/tmp/" + random_name;
}

}

