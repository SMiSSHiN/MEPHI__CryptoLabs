import json
import matplotlib.pyplot as plt

def weather_hist():
    with open('./data/weather.json', 'r') as f:
        weather = json.load(f)

    data = weather['hourly']['data']

    temp    = []
    hum     = []
    wind    = []
    cloud   = []
    ozone   = []
    urand   = [x for x in range(len(data) + 1)]

    for element in data:
        temp.append(element['temperature'])
        hum.append(element['humidity'])
        wind.append(element['windSpeed'])
        cloud.append(element['cloudCover'])
        ozone.append(element['ozone'])

    plt.rc('axes', axisbelow = True)
    plt.figure(figsize = (15, 15))
    plt.subplots_adjust(wspace = 0.4, hspace = 0.4)

    plt.subplot(321)
    plt.xlabel('Temperature')
    plt.ylabel('Probability')
    plt.title('Histogram of temp')
    plt.grid(True, linestyle = '--', linewidth = 0.5)
    plt.hist(temp, 15, density = 1, facecolor = 'b', alpha = 0.75)


    plt.subplot(322)
    plt.xlabel('Humidity')
    plt.ylabel('Probability')
    plt.title('Histogram of hum')
    plt.grid(True, linestyle = '--', linewidth = 0.5)
    plt.hist(hum, 15, density = 1, facecolor = 'g', alpha = 0.75)

    plt.subplot(323)
    plt.xlabel('Wind speed')
    plt.ylabel('Probability')
    plt.title('Histogram of wind')
    plt.grid(True, linestyle = '--', linewidth = 0.5)
    plt.hist(wind, 15, density = 1, facecolor = 'r', alpha = 0.75)

    plt.subplot(324)
    plt.xlabel('Cloud cover')
    plt.ylabel('Probability')
    plt.title('Histogram of cloud cover')
    plt.grid(True, linestyle = '--', linewidth = 0.5)
    plt.hist(cloud, 15, density = 1, facecolor = 'm', alpha = 0.75)

    plt.subplot(325)
    plt.xlabel('Ozon')
    plt.ylabel('Probability')
    plt.title('Histogram of ozon')
    plt.grid(True, linestyle = '--', linewidth = 0.5)
    plt.hist(cloud, 15, density = 1, facecolor = 'c', alpha = 0.75)

    plt.subplot(326)
    plt.xlabel('Uniform param')
    plt.ylabel('Probability')
    plt.title('Histogram of uniform dist')
    plt.grid(True, linestyle = '--', linewidth = 0.5)
    plt.hist(urand, 10, density = 1, facecolor = 'c', alpha = 0.75)

    plt.savefig('weather_hist.png')

def passwords_hist():
    with open('./data/passwords.json', 'r') as f:
        passwords = json.load(f)

    data = [bytes(pwd, 'utf-8')[0] for pwd in passwords]
    
    plt.rc('axes', axisbelow = True)
    plt.figure(figsize = (10, 10))
    plt.subplots_adjust(wspace = 0.4, hspace = 0.4)

    plt.xlabel('First byte of pwd')
    plt.ylabel('Probability')
    plt.title('Histogram of pwds')
    plt.grid(True, linestyle = '--', linewidth = 0.5)
    plt.hist(data, 15, density = 1, facecolor = 'b', alpha = 0.75)

    plt.savefig('passwords_hist.png')
    
if __name__ == '__main__':
    weather_hist()
