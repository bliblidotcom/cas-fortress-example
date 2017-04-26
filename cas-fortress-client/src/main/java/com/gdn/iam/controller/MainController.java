/*-
 * *
 * cas-fortress-client
 * ==================================
 * Copyright (C) 2017 Blibli.com
 * ==================================
 * Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 * *
 */
package com.gdn.iam.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class MainController {

  private static final String CATALOG = "catalog";
  private static final String PROFILE = "profile";

  private static final String CATALOG_PAGE = "/" + CATALOG;
  private static final String PROFILE_PAGE = "/" + PROFILE;


  @RequestMapping(path=CATALOG_PAGE, method = RequestMethod.GET)
  public String showCatalogPage() {
    return CATALOG;
  }

  @RequestMapping(path=PROFILE_PAGE, method = RequestMethod.GET)
  public String showProfilePage() {
    return PROFILE;
  }


}
