from datetime import datetime
import os



def write_file(filename, data):
    if os.path.isfile(filename):
        with open(filename, 'a') as f:
            f.write('\n' + data)
    else:
        with open(filename, 'w') as f:
            f.write(data)


def print_time():
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    data = "Current Time = " + current_time
    return data


write_file('test.txt', print_time())

pwd00 = input('Enter the file name to automate: ')
write_file=(pwd00, '')





# String	Meaning	Equivalent to
# @reboot	once on system startup
# @yearly	once yearly	0 0 1 1 *
# @monthly	once a month	0 0 1 * *
# @weekly	once a week	0 0 * * 0
# @daily	once a day	0 0 * * *
# @midnight	once a day at midnight	0 0 * * *
# @hourly	once an hour	0 * * * *
# once a minute	* * * * *
# once every day of the week	* * * * 1-5
# once every specific day, at a specific time (Sunday at 12:30)
#
