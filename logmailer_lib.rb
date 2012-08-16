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

    if log_config[:reject_global].class != Array
        abort("#{log_config[:name]} entry has malformed reject_global list")
    end

    if log_config[:reject_high].class != Array
        abort("#{log_config[:name]} entry has malformed reject_high list")
    end

    if log_config[:entry_tag].class != Array
        abort("#{log_config[:name]} entry has malformed entry_tag list")
    end
    log_config[:entry_tag].each do |entry_tag|
        if entry_tag.class != Array
            abort("#{log_config[:name]} entry has malformed entry_tag list")
        end
    end

    if log_config[:token_scan].class != Array
        abort("#{log_config[:name]} entry has malformed token_scan list")
    elsif log_config[:token_scan].length < 1
        abort("#{log_config[:name]} entry cannot have a blank token_scan list")
    end

    if log_config[:low_thresh].class != Fixnum
        abort("#{log_config[:name]} entry has malformed low_thresh number")
    end

    return true
end

