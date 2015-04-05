package com.tyy.Array;

public class Arrays {
	
	
	//can be replaced by System.arrayCopy
	public static <T> void rangeSet(T[] base, int start, int end, T[] beCopyed) {
		if(end>base.length) 
			end=base.length;
		if(start<0)
			start=0;
		if(start>=end)
			return;
		
	}

}
