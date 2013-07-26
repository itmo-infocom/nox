/* Copyright 2008 (C) Nicira, Inc.
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstring>
#include <string>
#include <fstream>
#include <iostream>
#include <iomanip>

#include "assert.hh"
#include "component.hh"
#include "vlog.hh"

#include "netinet++/datapathid.hh"
#include "netinet++/ethernetaddr.hh"
#include "netinet++/ethernet.hh"

#include "openflow/openflow-event.hh"
#include "openflow/openflow-datapath-join-event.hh"
#include "openflow/openflow-datapath-leave-event.hh"
using namespace vigil;
using namespace openflow;

namespace
{
Vlog_module slg("statcounter");

enum StatUpdateMode
{
    PassedValue,
    Increment
};

class StatCounter
{
private:
    StatUpdateMode update_mode;
    std::string file_path;
    bool error;
    static const int num_width = 10;
public:
    StatCounter(std::string path, StatUpdateMode mode) : update_mode(mode), file_path(path)
    {
	error = false;
        std::ofstream ofs(file_path, std::fstream::out);
        if (ofs.is_open())
        {
	    ofs.clear();
 	    ofs.close();
        }
	else
        {
	    VLOG_DBG(slg,"Sorry, can't open %s, no stats will be written",file_path.c_str());
            error = true;
	}
    }
    
    bool update_stats(std::string key, int value); 
};



bool StatCounter::update_stats(std::string key,int value)
{
    std::fstream file(file_path,std::fstream::in | std::fstream::out);
    if (file.is_open())
    {
         std::string line;
         bool found = false;

         while(std::getline(file,line))
         {
             if (line.substr(0,key.size()) == key)
             {
                 int num;
                 if (update_mode == StatUpdateMode::Increment)
                 {
                     std::stringstream ss(line.substr(key.size()+1));
                     if (!(ss >> num))                     
                          return false;
                     num++;
                 }
                 else
                     num = value;
                 
                 file.seekp(file.tellg() - num_width - 1);
                 file << std::setw(num_width) << num << std::endl;
                 found = true;
             }
         }
         file.close();
         if (!found)
         {
             std::ofstream file_2(file_path,std::ofstream::out | std::ofstream::app);
             file_2 << key << ' ' << std::setw(num_width) << 1 << std::endl;
             file_2.close();
         }
         return true;
    }
    else
	return false;
}

} // unnamed namespace
