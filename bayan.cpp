#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/crc.hpp>
#include <boost/uuid/detail/md5.hpp>
#include <fstream>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <set>
#include <memory>
#include <algorithm>
#include <string_view>
#include <span>

namespace po = boost::program_options;
namespace fs = boost::filesystem;
namespace algo = boost::algorithm;

using namespace std;

// Хеш-функции
enum class HashAlgorithm { CRC32, MD5 };

struct FileInfo {
    fs::path path;
    uintmax_t size;
    vector<string> block_hashes;
};

string compute_hash(span<const char> block, HashAlgorithm algorithm) {
    if (algorithm == HashAlgorithm::CRC32) {
        boost::crc_32_type result;
        result.process_bytes(block.data(), block.size());
        return to_string(result.checksum());
    } else { // MD5
        boost::uuids::detail::md5 hash;
        boost::uuids::detail::md5::digest_type digest;
        
        hash.process_bytes(block.data(), block.size());
        hash.get_digest(digest);
        
        const auto charDigest = reinterpret_cast<const char*>(&digest);
        return string(charDigest, charDigest + sizeof(boost::uuids::detail::md5::digest_type));
    }
}

// Чтение файла блоками и вычисление хешей
vector<string> compute_file_hashes(const fs::path& filepath, size_t block_size, HashAlgorithm algorithm) {
    vector<string> hashes;
    ifstream file(filepath, ios::binary);
    
    if (!file) {
        throw runtime_error("Cannot open file: " + filepath.string());
    }
    
    vector<char> buffer(block_size, 0);
    while (file) {
        file.read(buffer.data(), static_cast<streamsize>(block_size));
        const streamsize bytes_read = file.gcount();
        
        if (bytes_read == 0) break;
        
        // Дополняем нулями, если необходимо
        if (bytes_read < static_cast<streamsize>(block_size)) {
            fill(buffer.begin() + bytes_read, buffer.end(), 0);
        }
        
        hashes.push_back(compute_hash({buffer.data(), static_cast<size_t>(bytes_read)}, algorithm));
    }
    
    return hashes;
}

bool matches_masks(string_view filename, span<const string> masks) {
    if (masks.empty()) return true;
    
    string lower_name(filename);
    algo::to_lower(lower_name);
    
    return any_of(masks.begin(), masks.end(), [&](const string& mask) {
        string lower_mask(mask);
        algo::to_lower(lower_mask);
        
        if (algo::ends_with(lower_mask, ".*")) {
            string_view prefix = string_view(lower_mask).substr(0, lower_mask.size() - 2);
            return algo::starts_with(lower_name, prefix);
        }
        return algo::iends_with(filename, lower_mask);
    });
}

// Проверка, находится ли файл в исключенной директории
bool is_excluded(const fs::path& filepath, span<const fs::path> excluded_dirs) {
    const string file_str = filepath.string();
    return any_of(excluded_dirs.begin(), excluded_dirs.end(), [&](const fs::path& dir) {
        return algo::starts_with(file_str, dir.string());
    });
}

// Рекурсивный поиск файлов
vector<FileInfo> find_files(span<const fs::path> directories,
                           span<const fs::path> excluded_dirs,
                           span<const string> masks,
                           uintmax_t min_size,
                           int scan_level) {
    vector<FileInfo> files;
    
    for (const auto& dir : directories) {
        if (!fs::exists(dir) || !fs::is_directory(dir)) {
            cerr << "Warning: Directory not found or not accessible: " << dir << endl;
            continue;
        }
        
        const auto process_file = [&](const fs::directory_entry& entry) {
            if (fs::is_regular_file(entry.status())) {
                if (is_excluded(entry.path(), excluded_dirs)) {
                    return false;
                }
                
                const uintmax_t size = fs::file_size(entry.path());
                if (size >= min_size && matches_masks(entry.path().filename().string(), masks)) {
                    files.emplace_back(FileInfo{entry.path(), size, {}});
                }
            }
            return true;
        };
        
        if (scan_level < 0) {
            for (const auto& entry : fs::recursive_directory_iterator(dir)) {
                process_file(entry);
            }
        } else {
            fs::recursive_directory_iterator it(dir), end;
            while (it != end) {
                if (it.depth() > scan_level) {
                    it.disable_recursion_pending();
                }
                
                process_file(*it);
                
                try {
                    ++it;
                } catch (const fs::filesystem_error& e) {
                    cerr << "Warning: " << e.what() << endl;
                    it.pop();
                }
            }
        }
    }
    
    return files;
}

bool compare_files(FileInfo& file1, FileInfo& file2, size_t block_size, HashAlgorithm algorithm) {
    if (file1.size != file2.size) return false;
    
    // есть ли уже вычисленные хеши?
    size_t blocks_to_compare = max(file1.block_hashes.size(), file2.block_hashes.size());
    
    for (size_t i = 0; i < blocks_to_compare; ++i) {
        // Вычисляем хеш для file1 (если нужно)
        if (i >= file1.block_hashes.size()) {
            try {
                auto hashes = compute_file_hashes(file1.path, block_size, algorithm);
                file1.block_hashes.insert(file1.block_hashes.end(), 
                                        make_move_iterator(hashes.begin()),
                                        make_move_iterator(hashes.end()));
            } catch (const exception& e) {
                cerr << "Error reading file " << file1.path << ": " << e.what() << endl;
                return false;
            }
        }
        
        // Вычисляем хеш для file2 (если нужно)
        if (i >= file2.block_hashes.size()) {
            try {
                auto hashes = compute_file_hashes(file2.path, block_size, algorithm);
                file2.block_hashes.insert(file2.block_hashes.end(),
                                        make_move_iterator(hashes.begin()),
                                        make_move_iterator(hashes.end()));
            } catch (const exception& e) {
                cerr << "Error reading file " << file2.path << ": " << e.what() << endl;
                return false;
            }
        }
        
        // Сравниваем
        if (file1.block_hashes[i] != file2.block_hashes[i]) {
            return false;
        }
    }
    
    return true;
}

// Поиск дубликатов среди файлов
vector<vector<fs::path>> find_duplicates(vector<FileInfo>& files, size_t block_size, HashAlgorithm algorithm) {
    vector<vector<fs::path>> duplicates;
    vector<bool> processed(files.size(), false);
    
    for (size_t i = 0; i < files.size(); ++i) {
        if (processed[i]) continue;
        
        vector<fs::path> group;
        group.push_back(files[i].path);
        
        for (size_t j = i + 1; j < files.size(); ++j) {
            if (!processed[j] && files[i].size == files[j].size) {
                if (compare_files(files[i], files[j], block_size, algorithm)) {
                    group.push_back(files[j].path);
                    processed[j] = true;
                }
            }
        }
        
        if (group.size() > 1) {
            duplicates.push_back(move(group));
        }
    }
    
    return duplicates;
}

int main(int argc, char* argv[]) {
    try {
        po::options_description desc("Allowed options");
        desc.add_options()
            ("help,h", "Show help message")
            ("directories,d", po::value<vector<string>>()->multitoken(), "Directories to scan")
            ("exclude,e", po::value<vector<string>>()->multitoken(), "Directories to exclude")
            ("level,l", po::value<int>()->default_value(-1), "Scan level (0 - only specified directory, -1 - unlimited)")
            ("min-size,m", po::value<uintmax_t>()->default_value(1), "Minimum file size in bytes")
            ("mask", po::value<vector<string>>()->multitoken(), "File name masks (case insensitive)")
            ("block-size,b", po::value<size_t>()->default_value(1024), "Block size in bytes")
            ("hash", po::value<string>()->default_value("crc32"), "Hash algorithm (crc32 or md5)")
        ;
        
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
        
        if (vm.count("help")) {
            cout << desc << endl;
            return 0;
        }
        
        if (!vm.count("directories")) {
            cerr << "Error: At least one directory must be specified" << endl;
            return 1;
        }
        
        vector<fs::path> directories;
        for (const auto& dir : vm["directories"].as<vector<string>>()) {
            directories.emplace_back(dir);
        }
        
        vector<fs::path> excluded_dirs;
        if (vm.count("exclude")) {
            for (const auto& dir : vm["exclude"].as<vector<string>>()) {
                excluded_dirs.emplace_back(dir);
            }
        }
        
        vector<string> masks;
        if (vm.count("mask")) {
            masks = vm["mask"].as<vector<string>>();
        }
        
        uintmax_t min_size = vm["min-size"].as<uintmax_t>();
        int scan_level = vm["level"].as<int>();
        size_t block_size = vm["block-size"].as<size_t>();
        
        HashAlgorithm algorithm;
        string hash_algo = vm["hash"].as<string>();
        if (hash_algo == "crc32") {
            algorithm = HashAlgorithm::CRC32;
        } else if (hash_algo == "md5") {
            algorithm = HashAlgorithm::MD5;
        } else {
            cerr << "Error: Unknown hash algorithm. Use 'crc32' or 'md5'" << endl;
            return 1;
        }
        
        // Находим все файлы
        auto files = find_files(directories, excluded_dirs, masks, min_size, scan_level);
        
        // Находим дубликаты
        auto duplicates = find_duplicates(files, block_size, algorithm);
        
        // Выводим результаты
        for (const auto& group : duplicates) {
            for (const auto& file : group) {
                cout << file.string() << endl;
            }
            cout << endl;
        }
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}