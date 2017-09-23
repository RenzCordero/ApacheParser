from setuptools import setup, find_packages
setup(name='pyapache',
      version='0.1',
      description='Apache Parser',
      keywords=['Apache', 'Log'],
      url='https://github.com/RenzCordero/ApacheParser',
      author='Renz C. Cordero',
      author_email='corderorenz@gmail.com',
      packages=find_packages(),
      install_requires=[
          'maxminddb-geolite2'
      ])