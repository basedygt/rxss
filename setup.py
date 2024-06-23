import io
from setuptools import setup, find_packages
from os import path

pwd = path.abspath(path.dirname(__file__))
with io.open(path.join(pwd, 'README.md'), encoding='utf-8') as readme:
    desc = readme.read()

setup(
    name='rxss',
    version='0.0.1.post2',
    description='Tool to check reflecting params and paths in a bunch of URLs',
    long_description=desc,
    long_description_content_type='text/markdown',
    author='basedygt',
    license='Apache-2.0 License',
    url='https://github.com/basedygt/rxss',
    packages=find_packages(),
    classifiers=[
        'Topic :: Security',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
    ],
    keywords=['rxss', 'Reflected Cross Site Scripting', 'Pentest tools'],
    install_requires=['qsreplace'],
    entry_points={
        'console_scripts': [
            'rxss = rxss:main',
        ],
    },
)
