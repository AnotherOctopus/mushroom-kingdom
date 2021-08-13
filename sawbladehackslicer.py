
class Prusahackmushroomcutter():

    def __init__(self):
        self.posorder = [(0,0)]
        #                       (X, Z)
        self.sawstartpositions = [ (4.0,4.0),
                            (1.0,1.0),
                            (2.0,2.0),
                            (3.0,3.0)
                            ]
        self.mushroomholeheight = 5.0
        self.sawingwidth = 5.0
        self.numberofmotions = 100

    
    def cutmushroom(self,mushpos):
        sawstartpos = self.sawstartpositions[mushpos]
        self.posorder.append( (0,self.posorder[-1][1]) )
        self.posorder.append( (0,sawstartpos[1]) )
        self.posorder.append(    sawstartpos )

        sawstepsize = self.mushroomholeheight/self.numberofmotions
        sawpos = sawstartpos
        goingleft = 1
        for i in range(self.numberofmotions):
            sawpos = (sawpos[0] + goingleft*self.sawingwidth,sawpos[1] + sawstepsize )
            self.posorder.append(sawpos)
            goingleft = -goingleft

    def dumpgcode(self,gcodefile):
        movetoline = "G1 Z{} E{}\n"
        with open(gcodefile,"w+") as fh:
            for stepX,stepZ in self.posorder:
                fh.write(movetoline.format(stepZ,stepX))

if __name__ == "__main__":
    mushroomslicer = Prusahackmushroomcutter()
    mushroomslicer.cutmushroom(0)
    mushroomslicer.cutmushroom(1)
    mushroomslicer.dumpgcode("outcutfile.gcode")