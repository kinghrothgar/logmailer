#!/usr/bin/ruby

def ls_directory(path)
    begin
        filenames = Dir.open(path).entries
        ret = Array.new
        filenames.each do |filename|
            ret.push(path + filename)
        end
        return ret
    rescue
        return Array.new
    end
end

def config_check?(log_config)
    abort("An entry is missing a name") if log_config[:name].nil?

    if log_config[:files].class != Array
        abort("#{log_config[:name]} entry has malformed files list")     
    end

    if log_config[:delimiters].class != Array
        abort("#{log_config[:name]} entry has malformed delimiters list")
    elsif log_config[:delimiters].length < 1
        log_config[:delimiters] = [ /^[^\n\r]/ ]
    end

    if log_config[:entry_search].class != Array
        abort("#{log_config[:name]} entry has malformed entry_search list")
    elsif log_config[:entry_search].length < 1
        log_config[:entry_search] = [ /./ ]
    end

    if log_config[:entry_reject].class != Array
        abort("#{log_config[:name]} entry has malformed entry_reject list")
    end

    if log_config[:token_scan].class != Array
        abort("#{log_config[:name]} entry has malformed token_scan list")
    elsif log_config[:token_scan].length < 1
        abort("#{log_config[:name]} entry cannot have a blank token_scan list")
    end

    return true
end

