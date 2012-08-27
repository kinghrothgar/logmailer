#!/usr/bin/ruby
require 'rubygems'
# DEBUG:
require '/home/ldap/luke.jolly/git/logmailer/logmailer_lib.rb'
#require '<%= node[:logmailer][:full_path]+node[:logmailer][:lib] %>'

#########################################################################################
#                                                                                       #
# :name => The name of this log. Doesn't have to correspond to anything, is only used   #
#             for debugging                                                             #
#                                                                                       #
# :files => Array of full-path files. Use the Dir class if you want everything in a     #
#             directory                                                                 #
#                                                                                       #
# :delimiters => Array of delimiters (regex). Logmailer looks at each line of the file  #
#             as it comes in. If it finds one of these delimiters it knows the last     #
#              entry has ended and the next one has started                             #
#                                                                                       #
# :entry_search => Array of regex. If an entry matches any of these regexes, and        #
#             none of the reject_global or reject_high regexes, it is HIGH priority.    #
#             If an entry doesn't match any of these, doesn't match reject_global, but  #
#             still matches one of the token_scans it is LOW priority (doesn't get      #
#             emailed unless it breaks low_thresh in a minute)                          #
#                                                                                       #
# :reject_global => Array of regex. If an entry matched any of these, it is rejected    #
#             from both HIGH and LOW.                                                   #
#                                                                                       #
# :reject_high => Array of regex.  If an entry matches any of these, it is rejected     #
#             from HIGH and treated as LOW priority.                                    #
#                                                                                       #
# :entry_tag => Array of arrays.  Each array's first element is a string which is the   #
#             tag. The second element is a regex. All HIGH and LOW entries are checked. # 
#             If there's a match, the entry's tag becomes the corresponding tag. If     #
#             there is no match, the entry's tag is it's priority (either "HIGH" or     #
#             "LOW"). This tag is put in the subject line of emails to help with rules. #
#             This does not change what priority the entry is sorted as.                #
#                                                                                       #
# :token_scan => Array of regex. Each entry whether HIGH or LOW priority is matched     #
#             against these tokens. Each needs some sort of matching in them            #
#             (aka, parenthesis). The elements matched will be used to build the hash   #
#             which determines if this identical (or similar enough) entry has already  #
#             been seen (used for summary mode). Thus if two entries result in the same #
#             tokens they are grouped as the same error.                                #
#                                                                                       #
#########################################################################################

LOG       = true
LOGDIR    = "/home/ldap/luke.jolly/git/logmailer/logs"

CONFIG = [

#    <%if node[:roles].include? "mongo_nodes" -%>
    {
        :name           => "mongo_log",
        :files          => ls_directory("/var/log/mongo/").grep(/mongod\d*\.log$/),
        :delimiters     => [ /\n/ ],
        :entry_search   => [],
        :reject_global  => [],
        :reject_high    => [],
        :entry_tag      => [],
        :token_scan     => [ /\[.*\].([^ ]+)\s+([^ ]+)\s+([^ ]+)/ ],
        :low_thresh     => 20 
    },
#    <% end -%>

    {
        :name           => "disk_subsystem",
        :files          => [ "/var/log/disk_subsystem.log" ],
        :delimiters     => [ /\n/ ],
        :entry_search   => [ /./],
        :reject_global  => [],
        :reject_high    => [],
        :entry_tag      => [],
        :token_scan     => [ /([^:]+):/ ],
        :low_thresh     => 0
    },
    {
        :name           => "chef_log",
        :files          => [ "/var/log/chef/client.log" ],
        :delimiters     => [ /^\[.+\]/ ],
        :entry_search   => [ /FATAL:/ , /Transaction Check Error:/],
        :reject_global  => [ /Sleeping\sfor\s[0-9]+\sseconds/i ],
        :reject_high    => [],
        :entry_tag      => [],
        :token_scan     => [ /FATAL:\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)/ ],
        :low_thresh     => 0
    }
]

CONFIG.each do |log_config|
    config_check?(log_config)
end
