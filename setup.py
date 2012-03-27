from setuptools import setup, find_packages
import sys

version = '1.0dev'

install_requires = [
        'isodate',
        'requests',
        ]
if sys.version_info<(2,7):
    install_requires.append('argparse')

setup(name='clouddns',
      version=version,
      description='Rackspace Cloud DNS management tool',
      long_description=open('README.rst').read() + '\n' + \
              open('changes.rst').read(),
      classifiers=[
          'License :: DFSG approved',
          'License :: OSI Approved :: BSD License',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          ],
      keywords='Rackspace DNS clouddns',
      author='Wichert Akkerman',
      author_email='wichert@wiggy.net',
      url='https://github.com/wichert/clouddns',
      license='BSD',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      include_package_data=True,
      zip_safe=True,
      install_requires=install_requires,
      entry_points='''
      [console_scripts]
      clouddns = clouddns:main
      '''
      )
