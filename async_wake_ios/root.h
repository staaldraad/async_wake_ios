//
//  root.h
//  async_wake_ios
//
//  Created by Etienne Stalmans on 14/12/2017.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#ifndef root_h
#define root_h

#include <stdio.h>

uid_t get_root(void);
void reset_root(uid_t);
#endif /* root_h */
