#!/usr/bin/ruby

require 'socket'
require 'rubygems'
require 'daemons'
require 'file/tail'
require 'thread'

RECIPIENT = "Luke <luke.jolly@escapemg.com>, CoolestKidErverer <brian@grooveshark.com>, " +
            "Nick <nicholas.antonelli@escapemg.com>, Colin <colin.hostert@escapemg.com>"
HOSTNAME  = (Socket.gethostname).slice! /([A-Za-z0-9\-_])+/
SENDER    = "TestLogMailer <testlogmailer@#{HOSTNAME}.in.escapemg.com>"
SENDMAIL  = "/usr/sbin/sendmail -t"

# Can be turned on and off and directory set in the config file
def puts_log(filename, message)
    # If LOG is false, return and do not log
    if LOG
        time = Time.now.strftime("[%Y/%m/%d %H:%M:%S]")
        log = filename.gsub("/", ".").sub(/^\./, "")
        File.open("#{LOGDIR}/#{log}", 'a') do |f| 
            f.puts time + " " + message.to_s
        end
    end
end

# Builds an email for sendmail
# Called by send_and_reset
def make_message(sender, recipient, subject, body)
  msg = <<END_OF_MESSAGE
to:#{recipient}
from:#{sender}
subject:#{subject}


#{body} 
END_OF_MESSAGE
end

# Build subject and body and send email.  Also resets :cycle, :t_count, 
# and :flag for collect hashes. Requires :sub_tag to already be set 
# in token_hash
# Called by mail_and_garbage
def send_and_reset(filename, token_hash)
    # If the token hash is not in collect, construct the message this way
    if token_hash[:t_count].nil?
        message = "The following error occurred " +
            token_hash[:c_count].to_s +
            " times in the last minute:\n\n" +
            token_hash[:entry]
    # If it is in collect, construct message differently and reset
    else
        per_min = token_hash[:t_count]/token_hash[:cycle]
        message = "The following error occurred " +
                token_hash[:t_count].to_s +
                " times in the last #{token_hash[:cycle]}" +
                " minutes (#{per_min}/min):\n\n" +
                token_hash[:entry]
        token_hash[:cycle] = 0
        token_hash[:t_count] = 0
        token_hash[:flag] = :checked
    end
    
    subject = "[#{HOSTNAME}] (#{token_hash[:sub_tag]}) #{filename}"
    mail = make_message(SENDER, RECIPIENT, subject, message)
    
    # Send the email with error rescuing
    begin
        File.popen(SENDMAIL, "w") do |pipe|
            pipe.write(mail)
        end
    rescue
        $stderr.puts "Exception sending email."
        puts_log(filename, "ERROR: Exception sending email.")
    end
end

# Returns true if entry matches a search regex and no reject regex
# Called by analyze_lines
def entry_check(entry, search, reject)
    passed = false
    search.each do |s|
        if entry =~ s
            passed = true
            break
        end
    end
    return false unless passed

    reject.each do |r|
        return false if entry =~ r
    end
    return true
end

# Scans entry for tokens and returns set that's found. Returns 
# nil if none are found
# Called by analyze_lines
def token_scan(entry, tokens)
    tokens.each do |r|
        tokens_found = entry.scan(r)
        return tokens_found if tokens_found[0].class == Array
    end
    return
end

# Scans entry for subject tags right before first email. Returns nil
# if none match
# Called by mail_and_garbage 
def sub_tag_check(entry, tag)
    tag.each do |t|
        if entry =~ t[1]
            return t[0]
        end
    end
    return
end

# If one of the new entry delimiters is found, return true
# Called by logwatch
def delimiter_search(line, delimiters)
    delimiters.each do |d|
        return true if line =~ d
    end
    return false
end

# Indicates when we've read a full entry
# Called by logwatch
def get_state(entry_state, line, config)
    if delimiter_search(line, config[:delimiters])
        # if we've found a subsequent start, the last entry is done
        if entry_state == :started
            return :ended
        # if we've found a new start, we have a new log entry
        else
            return :started
        end
    end
    return entry_state # no state change
end

# Moves a token to summary and sets up new definitions. Run after
# first email is sent
# Called by mail_and_garbage
def collect(summary, source, tokens)
    summary[:collect][tokens] = summary[source][tokens]
    summary[source].delete(tokens)
    # How many emails have been sent
    summary[:collect][tokens][:e_count] = 1
    # Totaly error count since last email
    summary[:collect][tokens][:t_count] = 0
    # How many cycles have run since and email has been sent
    summary[:collect][tokens][:cycle] = 0
end

# Analyzes a complete entry and orginizes it into the summary hash.
# Called by logwatch
def analyze_lines(lines, summary, config)
    entry = lines.join("\n")

    # Check what priority it is, if neither, return. If :low_thresh is
    # set to 0, the :low check is skipped as it is turned off
    if entry_check(entry, config[:entry_search], config[:reject_high] + config[:reject_global])
        priority = :high
    elsif config[:low_thresh] != 0 and
            entry_check(entry, [/.*/], config[:reject_global])
        priority = :low
    else
        return
    end

    # Scan for tokens
    tokens = token_scan(entry,config[:token_scan])
    return if tokens.nil?
    # Glue them together with colons
    tokens = tokens[0].join(':')

    # If token exists in collect hash, increase count, else put into
    # correct priority hash
    if not summary[:collect][tokens].nil?
        summary[:collect][tokens][:c_count] += 1
    else
        # Initialize the summary data structure if not already setup
        # Note: ||= doesn't work with boolean
        summary[priority][tokens] ||= {}
        summary[priority][tokens][:flag] ||= :new
        summary[priority][tokens][:entry] = entry
        summary[priority][tokens][:c_count] ||= 0
        # Incrememnt counter
        summary[priority][tokens][:c_count] += 1
    end
end

# Runs every minute
# Called by logwatch
def mail_and_garbage(filename, summary, config)
    summary[:collect].keys.each do |k|
        # Increment cycle count
        summary[:collect][k][:cycle] += 1
        # Set to be emailed flag if error broke threshold last cycle
        if summary[:collect][k][:c_count] >= config[:low_thresh]
            summary[:collect][k][:flag] = :email
        end
        # Move current cycle count over to total cycle count and clear current
        summary[:collect][k][:t_count] += summary[:collect][k][:c_count]
        summary[:collect][k][:c_count] = 0
        # If only one email has been sent, collects for 5 minutes. If no email sent, 
        # keeps tokens in collect hash for another 5 minute period before deleting
        if summary[:collect][k][:e_count] == 1
            if summary[:collect][k][:flag] == :email and
                    (summary[:collect][k][:cycle] == 10 or
                     summary[:collect][k][:cycle] == 5)
                # Send email and reset :cycle, :t_count, :checked
                send_and_reset(filename, summary[:collect][k])
                summary[:collect][k][:e_count] += 1
            elsif summary[:collect][k][:cycle] == 10
                puts_log(filename, "INFO: Collect entry being deleted" +
                                   " (#{k} with #{summary[:collect][k][:t_count]} count):" +
                                   "\n#{summary[:collect][k][:entry]}")
                summary[:collect].delete(k)
            end
        # If two emails have been sent, collects for 10 minutes. If no email sent,
        # deletes from collect hash.
        elsif summary[:collect][k][:e_count] == 2
            if summary[:collect][k][:cycle] == 10
                if summary[:collect][k][:flag] == :email
                    # Send email and reset :cycle, :t_count, :checked
                    send_and_reset(filename, summary[:collect][k])
                else
                    puts_log(filename, "INFO: Collect entry being deleted" +
                                       " (#{k} with #{summary[:collect][k][:t_count]} count):" +
                                       "\n#{summary[:collect][k][:entry]}")
                    summary[:collect].delete(k)
                end
            end
        end
    end
 
    summary[:high].keys.each do |k|
        if summary[:high][k][:flag] != :new
            # Check if any of the tag regex match the entry, if none do
            # sub_tag_check returns nil
            summary[:high][k][:sub_tag] = sub_tag_check(summary[:high][k][:entry], config[:entry_tag])
            summary[:high][k][:sub_tag] ||= "HIGH"
            # Send email
            send_and_reset(filename, summary[:high][k])
            summary[:high].delete(k)
        else
            summary[:high][k][:flag] = :checked
        end
    end

    # If :low_thresh is 0, the last section is skipped and returns
    if config[:low_thresh] == 0
        return
    end
    summary[:low].keys.each do |k|
        if summary[:low][k][:flag] != :new
            if summary[:low][k][:c_count] >= config[:low_thresh]
                # Check if any of the tag regex match the entry, if none do
                # sub_tag_check returns nil
                summary[:low][k][:sub_tag] = sub_tag_check(summary[:low][k][:entry], config[:entry_tag])
                summary[:low][k][:sub_tag] ||= "LOW"
                # Send email
                send_and_reset(filename, summary[:low][k])
                # Move token to collect hash
                collect(summary, :low, k)
            else
                puts_log(filename, "INFO: Low entry being deleted" +
                                   " (#{k} with #{summary[:low][k][:c_count]} count):" +
                                   "\n#{summary[:low][k][:entry]}")
                summary[:low].delete(k)
            end
        else
            summary[:low][k][:flag] = :checked
        end
    end
end

    
# Main loop: creates email/garbage collect and tail threads, 
# and calls analyze_lines when we have a full line
def logwatch(filename, config)
    # Initialize the high, low, and collect hashes that will be shared between 
    # the tail/analyze thread and the email/garbage collect cycle thread
    summary = { :high => {}, :low => {} , :collect => {}}
    # Initialize the mutex to protect shared data (summary)
    mutex = Mutex.new

    # Start email/garbage collection thread which cycles every minute
    email_thread = Thread.new do
        while 1
            # Lock the mutex so summary doesn't get modified by tail_thread
            mutex.synchronize {mail_and_garbage(filename, summary, config)}
            sleep 60
        end
    end
    # Start tail thread
    tail_thread = Thread.new do
        File::Tail::Logfile.open(filename, :backward => 0) do |log|
            lines = []
            entry_state = :undefined

            log.tail do |line|
                entry_state = get_state(entry_state, line, config)
                # Partial entry, add current line to the lines buffer
                if entry_state == :started
                    lines << line.chomp
                # Full entry read into lines, analyze_lines is called 
                # and lines is reset with the start of the new entry
                elsif entry_state == :ended
                    # Lock the mutex so summary doesn't get modified by email_thread
                    mutex.synchronize do
                        analyze_lines(lines, summary, config)
                    end
                    lines = [line.chomp]
                    entry_state = :started
                # If entry_state is :undefined, no entry start has been read yet
                # so the current line is discarded and we move to the next
                end
            end
        end
    end
    # The joins keep the logwatch method from finishing before the threads have
    email_thread.join
    tail_thread.join
end

# Spawn a process to tail file_name
# Called by load_tails
def spawn_proc(file_name, log_config)
    if File.exists? file_name
        puts file_name
        pid = Process.fork
        if pid.nil?
            logwatch(file_name, log_config)
        else
            $pids[pid] = [file_name, log_config]
        end
    else
        puts "#{file_name} dne"
    end
end

# Every time this method runs, it gets a list of current logmailer children and their pids.
# It then runs through every item in the config, and for each one, checks if there is already
# a pid handling that item. If not it spawns one.
def load_tails()
    logmailer_pids = {}
    grep = "/bin/ps aux | /bin/grep logmailer | /bin/awk '{print $2}'"
    %x{#{grep}}.scan(/[0-9]+/).each do |ps|
        logmailer_pids[ps.to_i] = 1
    end

    $pids.each_key do |pid|
        $pids.delete(pid) if not logmailer_pids.has_key? pid
    end

    CONFIG.each do |log_config|
        log_config[:files].each do |file_name|
            spawn = true
            $pids.each_key do |pid|
                if $pids[pid][0].eql? file_name
                    spawn = false
                end
            end if not $pids.empty?
            spawn_proc(file_name, log_config) if spawn
            # Keeps them from spawning all at once so that all the mail_and_garbage
            # cycles don't run at the same exact time
            sleep 3 if spawn
        end
    end
end

# DEBUG: require '<%= node[:logmailer][:full_path]+node[:logmailer][:conf] %>'
require '/home/ldap/luke.jolly/git/logmailer/logmailer_conf.rb'

load_tails()

Daemons.daemonize # run in the background
while 1
    sleep 30
    Process.wait(-1,Process::WNOHANG) #reap dead children
    load_tails()
end
