"""Apache Parser.

Apache Log Parser
Author: Renz C. Cordero

"""
import re
import os
import logging
from geolite2 import geolite2
logging.basicConfig(level=logging.INFO)


class ApacheParser(object):
    """Apache Parser."""

    def __init__(self):
        """Initialize Variable."""
        self.__logger = logging.getLogger('ApacheParser')
        self.__logger.info('Initialize')
        self.__unique_ip = []
        self.__unique_ip_country = {}
        self.__per_ip_activity = {}
        self.__sqlinjections = []
        self.__dicts_ips = {}

    def read_logfile(self, logfile):
        """Read lines of log file."""
        self.__logger.info('Dry run...')
        for idx, lines in enumerate(open(logfile, 'r', errors='ignore')):
            self._collect_unique_ip(lines)
            self._get_ip_request_line(idx, lines)

            sqli_result = self._get_sqlinjection(idx, lines)
            if sqli_result:
                self.__sqlinjections.append(sqli_result)

        self.__logger.info(self.__sqlinjections)

    def _get_ip(self, lines):
        """Get all ip addresses on a string.

        Sample Shape:
        ['1.2.3.4', '5.6.7.8']
        """
        pattern = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        result = re.findall(pattern, lines)

        return result

    def _get_ip_request_line(self, idx, lines):
        """Get Ip and request line."""
        pattern = '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s(?:GET|POST|PUT|DELETE))'
        result = re.findall(pattern, lines)
        self.__logger.info(result)
        ip = None
        method = None
        flag = True
        try:
            result = result[0].split(' ')
            ip = result[0]
            method = result[1]
            flag = True
        except IndexError:
            flag = False
            # self.__logger.error('No Request Line found:' + str(idx))

        if flag:
            if ip in self.__per_ip_activity:
                if method not in self.__per_ip_activity[str(ip)]:
                    self.__per_ip_activity[str(ip)].append(method)
            else:
                self.__per_ip_activity[str(ip)] = [str(method)]

    def _collect_unique_ip(self, lines):
        """Collect Unique ip address."""
        reader = geolite2.reader()
        list_ips = self._get_ip(lines)
        for ip in list_ips:
            if ip not in self.__unique_ip:
                self.__unique_ip.append(ip)
                try:
                    if reader.get(ip) is not None and reader.get(ip).get('country') is not None:
                        # self.__logger.info(reader.get(ip))
                        self.__unique_ip_country[str(ip)] = {
                            "ip": ip,
                            "hits": 1,
                            "country_code": reader.get(ip).get('country').get('iso_code'),
                            "country_name": reader.get(ip).get('country').get('en')
                        }
                except ValueError:
                    self.__logger.error('Not a IPV4 or IPV6>>>>' + str(ip))
            else:
                #  Count how many times does the ip address exist on the flat file.
                try:
                    if reader.get(ip) is not None and reader.get(ip).get('country') is not None:
                        self.__unique_ip_country[str(ip)]['hits'] += 1
                except ValueError:
                    self.__logger.error('Not a IPV4 or IPV6>>>>' + str(ip))

    def list_unique_ip(self):
        """Return the list of Unique Ip addresses on flat file."""
        return sorted(self.__unique_ip)

    def list_unique_ip_country(self):
        """Return the list of Unique Ip Addresses with country on flat file."""
        return self.__unique_ip_country

    def list_per_ip_activity(self):
        """Return List of ip per activity on flat text file."""
        return self.__per_ip_activity

    def _create_log_file(self, dst, filename, data):
        self.__logger.info(dst)

        with open(os.path.join(dst, filename), 'w') as f:
            f.write(data)
            f.close

    def get_result(self, folder_location=None):
        """Create result of log file to a folder."""
        self.__logger.info('Creating output files')
        self.__logger.info(folder_location)
        if folder_location is None:
            folder_location = os.getcwd()
        self.__logger.info(os.path.exists(folder_location))
        if not os.path.exists(folder_location):
            os.makedirs(folder_location)

        data = ""
        # 1st parse the unique ip
        for ip in self.__unique_ip:
            data += ip + chr(10) + chr(13)

        self._create_log_file(folder_location, 'unique_ip.txt', data)

        data = ""
        # 2nd  parse unique ip with country and hits
        for key, value in self.__unique_ip_country.items():
            data += key + chr(9)
            data += 'country:' + value.get('country_code') + chr(9)
            data += 'hits:' + str(value.get('hits')) + chr(10) + chr(13)

        self._create_log_file(folder_location, 'unique_ip_country.txt', data)

        #3rd output ip per request line
        data = ""
        for key,value in self.__per_ip_activity.items():
            data += key + chr(9)
            data += 'method:' + str(value)+ chr(10) + chr(13)
        self._create_log_file(folder_location, 'ip_per_request.txt', data)

    def _get_sqlinjection(self, idx, lines):
        """Get all possible sqlinjection.

        Regex reference : https://www.symantec.com/connect/articles/detection-sql-injection-and-cross-site-scripting-attacks
        """
        sqli_dicts = {}

        list_pattern = [
            '/(\%27)|(\')|(\-\-)|(\%23)|(#)/ix',
            '/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i',
            '/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix',
            '/((\%27)|(\'))union/ix',
            '/((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/ix',
            '/((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/I',
            '/((\%3C)|<)[^\n]+((\%3E)|>)/I'

        ]
        for pattern in list_pattern:
            result = re.findall(pattern, lines)
            for data in result:
                if str(idx) not in sqli_dicts:
                    sqli_dicts[str(idx)] = [data]
                else:
                    sqli_dicts[str(idx)].append(data)

        return sqli_dicts

if __name__ == '__main__':
    AP = ApacheParser()
    AP.read_logfile(os.path.join(os.getcwd(), 'Logfile', 'sample.log'))
    AP.get_result(os.path.join(os.getcwd(), 'RESULT'))
