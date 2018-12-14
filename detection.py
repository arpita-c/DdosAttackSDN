import math

from pox.core import core

log = core.getLogger()

WINDOW_SIZE = 50
NO_OF_WINDOWS = 50
ENTROPY_THRESHOLD = 0.5

class Entropy(object):
	count = 0
	entDic = {}
	ipList = []
	dstEnt = []
	value = 1

	def statcolect(self, element):

		self.count +=1
		self.ipList.append(element)
		if self.count == WINDOW_SIZE:
			for i in self.ipList:
				if i not in self.entDic:
					self.entDic[i] =0
				self.entDic[i] +=1
			self.entropy(self.entDic)
			self.entDic = {}
			self.ipList = []
			self.count = 0

	def entropy (self, lists):
		l = WINDOW_SIZE
		elist = []
		for k,p in lists.items():
			c = p/float(l)
			c = abs(c)
			elist.append(-c * math.log(c, 10))
		entropy_calculated = sum(elist)
		log.info('Entropy = ' + str(entropy_calculated))
		self.dstEnt.append(entropy_calculated)
		if(len(self.dstEnt)) == NO_OF_WINDOWS:
			# Do some action if low entropy for long time
			avg_entropy = sum(self.dstEnt) / float(NO_OF_WINDOWS)
			print "Average entropy = " + str(avg_entropy)
			if self.value==0:
				percent_change = 100
			else:
				percent_change = (self.value - avg_entropy) * 100 / float(self.value)
			print "Percent drop = " + str(percent_change) + "%"
			if avg_entropy <= ENTROPY_THRESHOLD:
				print "**********\n***** DDOS DETECTED *****\n**********"
			self.dstEnt = []

                        self.value = avg_entropy

	def __init__(self):
		pass
