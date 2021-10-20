# mushroom-kingdom
Automating Mushrooms

# meta
project uses cost-effective COTS means to construct mushroom grow systems, automate farming, for various types of culinary mushrooms.

# sw
software for grow system
- chambercontroller
    - controller code for esp32-based sensor device. low level control only
- chambercoordinator
    - coordinator code that sets profiles per sensor device. profiles take advantage of low level control so deploying profiles is device agnostic
- sawbladehackslicer.py
    - script for toolhead used to remove mushrooms from grow container

# nutrient
nutrition info for various strains/species of mushrooms

# mcad
mechanical design files
- enclosure/fume hood
- grow container
- toolhead

# ecad
electrical design files
- esp32 sensor module
- fan4 motor controller
