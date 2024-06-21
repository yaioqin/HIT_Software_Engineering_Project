(function(){"use strict";var e={42662:function(e,t,s){var a=s(66848),n=s(56178),o=function(){var e=this,t=e._self._c;return t("div",{staticClass:"home"},[t("div",{staticClass:"top-bar"},[e._m(0),t("div",{staticClass:"right"},[t("router-link",{staticClass:"home-link",attrs:{to:"/login"}},[e._v("登录")]),t("router-link",{staticClass:"home-link",attrs:{to:"/register"}},[e._v("注册")])],1)]),t("div",{staticClass:"carousel"},[e._l(e.images,(function(s,a){return t("div",{key:a,staticClass:"carousel-item",class:{active:e.currentIndex===a}},[t("img",{attrs:{src:s.src,alt:s.alt}}),t("div",{staticClass:"carousel-caption",style:{color:2===a?"black":"white"},domProps:{innerHTML:e._s(s.caption)}})])})),t("button",{staticClass:"prev",on:{click:e.prevSlide}},[e._v("❮")]),t("button",{staticClass:"next",on:{click:e.nextSlide}},[e._v("❯")])],2),t("div",{staticClass:"dots"},e._l(e.images,(function(s,a){return t("span",{key:a,class:{active:e.currentIndex===a},on:{click:function(t){return e.goToSlide(a)}}})})),0),e._m(1)])},r=[function(){var e=this,t=e._self._c;return t("div",{staticClass:"left"},[t("span",[e._v("ChatWithAIs V1 | 一站式大语言模型访问平台")])])},function(){var e=this,t=e._self._c;return t("div",{staticClass:"sec-notice"},[t("br"),e._v("©2024 Created by HIT-ChatWithAIs team")])}],i={name:"HomeView",data(){return{images:[{src:s(955),alt:"homepage1",caption:"打造多大语言模型集成的智能助手平台，<br>为用户提供一站式信息查询服务。"},{src:s(3392),alt:"homepage2",caption:"实现一站式大语言模型访问，<br>支持ChatGPT、文心一言、通义千问。"},{src:s(27593),alt:"homepage3",caption:"关注系统的长期运行和维护，<br>确保系统为用户提供稳定、优质的服务。"}],currentIndex:0,intervalId:null}},mounted(){this.startCarousel()},methods:{startCarousel(){this.intervalId=setInterval((()=>{this.nextSlide()}),5e3)},nextSlide(){this.currentIndex=(this.currentIndex+1)%this.images.length},prevSlide(){this.currentIndex=(this.currentIndex-1+this.images.length)%this.images.length},goToSlide(e){this.currentIndex=e}},beforeDestroy(){clearInterval(this.intervalId)}},c=i,l=s(845),u=(0,l.A)(c,o,r,!1,null,"e7d1ff72",null),d=u.exports,g=function(){var e=this,t=e._self._c;return t("div",[e._m(0),t("div",{staticClass:"login-page"},[t("div",{staticClass:"login-container"},[t("h2",{staticClass:"login-title"},[e._v("欢迎回来！")]),t("form",{staticClass:"login-form",on:{submit:function(t){return t.preventDefault(),e.login.apply(null,arguments)}}},[t("div",{staticClass:"form-group"},[t("label",{attrs:{for:"username"}},[e._v("用户名：")]),t("input",{directives:[{name:"model",rawName:"v-model",value:e.username,expression:"username"}],staticClass:"input-field",attrs:{type:"text",required:""},domProps:{value:e.username},on:{input:function(t){t.target.composing||(e.username=t.target.value)}}})]),t("div",{staticClass:"form-group"},[t("label",{attrs:{for:"password"}},[e._v("密码：")]),t("input",{directives:[{name:"model",rawName:"v-model",value:e.password,expression:"password"}],staticClass:"input-field",attrs:{type:"password",required:""},domProps:{value:e.password},on:{input:function(t){t.target.composing||(e.password=t.target.value)}}})]),t("button",{staticClass:"login-button",attrs:{type:"submit"}},[e._v("登录")])]),t("p",{staticClass:"login-message"},[e._v(e._s(e.message))]),t("p",[e._v("还没有账号？ "),t("router-link",{attrs:{to:"/register"}},[e._v("点击这里注册")])],1)])])])},h=[function(){var e=this,t=e._self._c;return t("div",{staticClass:"top-bar"},[t("div",{staticClass:"left"},[t("span",[e._v("ChatWithAIs V1 | 一站式大语言模型访问平台")])])])}],m=(s(44114),s(98355));m.A.defaults.withCredentials=!0;var p={name:"Login",data(){return{username:"",password:"",message:""}},methods:{async login(){try{const e=await m.A.post("/api/login",{username:this.username,password:this.password},{withCredentials:!0});this.message=e.data.message,"admin"===e.data.role?Ae.push({name:"AdminDashboard"}):Ae.push({name:"UserDashboard"})}catch(e){this.message=e.response&&e.response.data?e.response.data.message:"登录失败，请稍后重试。"}}}},v=p,f=(0,l.A)(v,g,h,!1,null,"0ee12a98",null),A=f.exports,C=function(){var e=this,t=e._self._c;return t("div",[e._m(0),t("div",{staticClass:"register-page"},[t("div",{staticClass:"register-container"},[t("h2",{staticClass:"register-title"},[e._v("注册新账号")]),t("form",{staticClass:"register-form",on:{submit:function(t){return t.preventDefault(),e.register.apply(null,arguments)}}},[t("div",{staticClass:"form-group"},[t("label",{attrs:{for:"username"}},[e._v("用户名：")]),t("input",{directives:[{name:"model",rawName:"v-model",value:e.username,expression:"username"}],staticClass:"input-field",attrs:{type:"text",required:""},domProps:{value:e.username},on:{input:function(t){t.target.composing||(e.username=t.target.value)}}})]),t("div",{staticClass:"form-group"},[t("label",{attrs:{for:"password"}},[e._v("密码：")]),t("input",{directives:[{name:"model",rawName:"v-model",value:e.password,expression:"password"}],staticClass:"input-field",attrs:{type:"password",required:""},domProps:{value:e.password},on:{input:function(t){t.target.composing||(e.password=t.target.value)}}})]),t("button",{staticClass:"register-button",attrs:{type:"submit"}},[e._v("注册")])]),t("p",{staticClass:"register-message"},[e._v(e._s(e.message))]),t("p",[e._v("已有账号？ "),t("router-link",{attrs:{to:"/login"}},[e._v("点击这里登录")])],1)])])])},b=[function(){var e=this,t=e._self._c;return t("div",{staticClass:"top-bar"},[t("div",{staticClass:"left"},[t("span",[e._v("ChatWithAIs V1 | 一站式大语言模型访问平台")])])])}];m.A.defaults.withCredentials=!0;var w={name:"RegisterComponent",data(){return{username:"",password:"",message:""}},methods:{async register(){try{const e=await m.A.post("/api/register",{username:this.username,password:this.password});this.message=e.data.message,201===e.status&&(this.message+=" 2s后自动跳转到登录页面...",setTimeout((()=>{this.$router.push("/login")}),2e3))}catch(e){this.message=e.response&&e.response.data?e.response.data.message:"注册失败，请稍后重试。"}}}},k=w,_=(0,l.A)(k,C,b,!1,null,"d0d6808a",null),y=_.exports,S=function(){var e=this,t=e._self._c;return t("div",{staticClass:"home"},[t("div",{staticClass:"sidebar"},[t("div",{staticClass:"sidebar-header"},[t("h2",[e._v("历史聊天记录")]),t("transition",{attrs:{name:"button-fade"}},[t("el-button",{attrs:{type:"primary",icon:"el-icon-edit"},on:{click:e.CreateNewAndSave}},[e._v("创建并保存")])],1)],1),t("ul",e._l(e.themes,(function(s,a){return t("li",{key:a},[t("a",{staticClass:"truncate-text",attrs:{href:"#"+s.id},on:{click:function(t){return t.preventDefault(),e.get_conversation(s.id)}}},[e._v(e._s(s.summary))]),t("div",[t("el-button",{attrs:{type:"danger",icon:"el-icon-delete"},on:{click:function(t){return e.deleteConversation(s.id)}}})],1)])})),0)]),t("div",{staticClass:"home-right"},[t("div",{staticClass:"right-version"},[e._m(0),t("div",{staticClass:"user-actions"},[t("button",{staticClass:"action-button logout-button",on:{click:e.goToLogout}},[e._v("登出")]),t("button",{staticClass:"action-button feedback-button",on:{click:e.goToFeedback}},[e._v("反馈")])])]),t("div",{ref:"messageContainer",staticClass:"right-body",class:0===e.wenxin_messages.length?"nodata":""},[t("div",{staticClass:"container"},[t("div",{staticClass:"left"},e._l(e.wenxin_messages,(function(a,n){return t("div",{key:n,staticClass:"main-message",class:{"user-message":"user"===a.role,"friend-message":"assistant"===a.role}},[t("div",{staticClass:"message-role",class:{"user-message":"user"===a.role,"friend-message":"assistant"===a.role}},["user"===a.role?t("img",{attrs:{src:s(14487),alt:"User Icon"}}):"assistant"===a.role?t("img",{attrs:{src:s(74970),alt:"Friend Icon"}}):e._e(),t("span",{staticClass:"message-role-name",class:"user"===a.role?"user-color":"friend-color"},[e._v(e._s(a.role)+":")])]),"user"===a.role?t("div",{staticClass:"user-message"},[e._v(e._s(a.content))]):t("div",{staticClass:"friend-message",domProps:{innerHTML:e._s(e.renderMessage(a.content))}})])})),0),t("div",{staticClass:"mid"},e._l(e.tongyi_messages,(function(a,n){return t("div",{key:n,staticClass:"main-message",class:{"user-message":"user"===a.role,"friend-message":"assistant"===a.role}},[t("div",{staticClass:"message-role",class:{"user-message":"user"===a.role,"friend-message":"assistant"===a.role}},["user"===a.role?t("img",{attrs:{src:s(14487),alt:"User Icon"}}):"assistant"===a.role?t("img",{attrs:{src:s(15604),alt:"Friend Icon"}}):e._e(),t("span",{staticClass:"message-role-name",class:"user"===a.role?"user-color":"friend-color"},[e._v(e._s(a.role)+":")])]),"user"===a.role?t("div",{staticClass:"user-message"},[e._v(e._s(a.content))]):t("div",{staticClass:"friend-message",domProps:{innerHTML:e._s(e.renderMessage(a.content))}})])})),0),t("div",{staticClass:"right"},e._l(e.chatgpt_messages,(function(a,n){return t("div",{key:n,staticClass:"main-message",class:{"user-message":"user"===a.role,"friend-message":"system"===a.role}},[t("div",{staticClass:"message-role",class:{"user-message":"user"===a.role,"friend-message":"system"===a.role}},["user"===a.role?t("img",{attrs:{src:s(14487),alt:"User Icon"}}):"system"===a.role?t("img",{attrs:{src:s(61927),alt:"Friend Icon"}}):e._e(),t("span",{staticClass:"message-role-name",class:"user"===a.role?"user-color":"friend-color"},[e._v(e._s(a.role)+":")])]),"user"===a.role?t("div",{staticClass:"user-message"},[e._v(e._s(a.content))]):t("div",{staticClass:"friend-message",domProps:{innerHTML:e._s(e.renderMessage(a.content))}})])})),0)])]),t("div",{staticClass:"right-input",on:{keyup:function(t){return!t.type.indexOf("key")&&e._k(t.keyCode,"enter",13,t.key,"Enter")?null:e.handleSearch.apply(null,arguments)}}},[t("el-input",{staticClass:"input",attrs:{placeholder:"给Chat Demo发送消息"},model:{value:e.queryKeyword,callback:function(t){e.queryKeyword=t},expression:"queryKeyword"}}),e.loading?e._e():t("el-button",{attrs:{type:"primary"},on:{click:e.handleSearch}},[t("img",{staticClass:"up-load",attrs:{src:s(24490)}})]),e.loading?t("el-button",{attrs:{type:"primary"},on:{click:e.closeEventSource}},[t("img",{staticClass:"up-load",attrs:{src:s(89910)}})]):e._e()],1),t("div",{staticClass:"sec-notice"},[e._v("Chat Demo may also make mistakes. Please consider checking important information.")])])])},x=[function(){var e=this,t=e._self._c;return t("div",{staticClass:"llm-chat-demo"},[t("span",{staticClass:"chat-demo"},[e._v("ChatWIthAIs")]),t("span",{staticClass:"version"},[e._v(" V1")])])}],E=s(80642),B=s(92464),I=s(72563),O=s.n(I),U=s(86697),M=s(5163),R=s(81109),F=s(53873),T=s.n(F),N={name:"UserDashboard",components:{},computed:{html(){return this.md.render(this.messages)}},data(){return{md:(new E.A).use(B.A).use(O(),{enabled:!0}).use(U.A).use(M.A,"warning").use(T(),{hljs:R.A}),current_id:null,queryKeyword:"",tempResult:{},flag:0,loading:!1,wenxin_messages:[],tongyi_messages:[],chatgpt_messages:[],socket:null,eventSource:null,stopIcon:"@/assets/等待.png",uploadIcon:"@/assets/上传.png",themes:[]}},created(){this.fetchThemes()},methods:{get_conversation(e){this.flag=0,this.current_id=e,fetch(`/api/conversations/get_conversation?id=${e}`,{method:"GET",credentials:"include"}).then((e=>{if(!e.ok)throw new Error("Network response was not ok");return e.json()})).then((e=>{this.chatgpt_messages=e.chatgpt_messages,this.tongyi_messages=e.tongyi_messages,this.wenxin_messages=e.wenxin_messages})).catch((e=>{console.error("Error:",e.message)}))},fetchThemes(){fetch("/api/conversations/get_conversation_summary",{method:"GET",credentials:"include"}).then((e=>{if(!e.ok)throw new Error("Network response was not ok");return e.json()})).then((e=>{this.themes=e})).catch((e=>{console.error("Error:",e.message)}))},CreateNewAndSave(){null==this.current_id?fetch("/api/conversations/new_conversation",{method:"POST",headers:{"Content-Type":"application/json"}}).then((e=>{if(!e.ok)throw new Error("Failed to create and save conversation");return e.json()})).then((e=>{alert("Conversation created and saved successfully."),this.messages_chatgpt=[],this.messages_tongyi=[],this.messages_wenxin=[],this.current_id=null,window.location.reload(),this.fetchThemes()})).catch((e=>{console.error("Error:",e.message),alert("Failed to create and save conversation")})):fetch("/api/conversations/update_conversation?id="+this.current_id,{method:"PUT",headers:{"Content-Type":"application/json"}}).then((e=>{if(!e.ok)throw new Error("Failed to update conversation");return e.json()})).then((e=>{alert("Conversation updated successfully."),this.messages_chatgpt=[],this.messages_tongyi=[],this.messages_wenxin=[],this.current_id=null,window.location.reload(),this.fetchThemes()})).catch((e=>{console.error("Error:",e.message),alert("Failed to update conversation")}))},renderMessage(e){return null==this.current_id||this.flag?e:this.md.render(e)},deleteConversation(e){m.A.delete("api/conversations/delete_conversation?id="+e).then((e=>{console.log(e.data.message)})).catch((e=>{console.error("Error deleting conversation:",e)})),window.location.reload(),this.fetchThemes()},async handleSearch(){if(this.loading)return;this.flag=1;const e=this.queryKeyword;this.loading=!0;try{let t="zxa",s={orgcontent:"",content:"",role:"assistant",zxakey:t},a={orgcontent:"",content:"",role:"assistant",zxakey:t},n={orgcontent:"",content:"",role:"system",zxakey:t};this.wenxin_messages.push({content:e,role:"user"}),this.tongyi_messages.push({content:e,role:"user"}),this.chatgpt_messages.push({content:e,role:"user"}),this.$nextTick((()=>{this.scrollToBottom()}));let o=s;this.wenxin_eventSource=new EventSource("/api/wenxin?query="+e,{withCredentials:!0}),this.wenxin_eventSource.onmessage=e=>{try{const t=JSON.parse(e.data);"done"===t.message&&(this.wenxin_eventSource.close(),this.loading=!1),"done"!=t.message&&(o.orgcontent+=t.message.toLocaleString(),o.orgcontent=o.orgcontent.replace(/\*\*\s*([^*]*?)\s*(:\s*)?\*\*/g,"**$1$2**"),o.content=this.md.render(o.orgcontent)),this.scrollToBottom()}catch(t){console.error("Error parsing JSON:",t)}},this.wenxin_messages.push(s),this.queryKeyword="",this.wenxin_eventSource.onerror=e=>{console.error("EventSource failed:",e),this.wenxin_eventSource.close()};let r=a;this.tongyi_eventSource=new EventSource("/api/tongyi?query="+e,{withCredentials:!0}),this.tongyi_eventSource.onmessage=e=>{try{const t=JSON.parse(e.data);"done"===t.message&&(this.tongyi_eventSource.close(),this.loading=!1),"done"!=t.message&&(r.orgcontent+=t.message.toLocaleString(),r.orgcontent=r.orgcontent.replace(/\*\*\s*([^*]*?)\s*(:\s*)?\*\*/g,"**$1$2**"),r.content=this.md.render(r.orgcontent)),this.scrollToBottom()}catch(t){console.error("Error parsing JSON:",t)}},this.tongyi_messages.push(a),this.queryKeyword="",this.tongyi_eventSource.onerror=e=>{console.error("EventSource failed:",e),this.tongyi_eventSource.close()};let i=n;this.chatgpt_eventSource=new EventSource("/api/chatgpt?query="+e,{withCredentials:!0}),this.chatgpt_eventSource.onmessage=e=>{try{const t=JSON.parse(e.data);"done"===t.message&&(this.chatgpt_eventSource.close(),this.loading=!1),"done"!=t.message&&(i.orgcontent+=t.message.toLocaleString(),i.orgcontent=i.orgcontent.replace(/\*\*\s*([^*]*?)\s*(:\s*)?\*\*/g,"**$1$2**"),i.content=this.md.render(i.orgcontent)),this.scrollToBottom()}catch(t){console.error("Error parsing JSON:",t)}},this.chatgpt_messages.push(n),this.queryKeyword="",this.chatgpt_eventSource.onerror=e=>{console.error("EventSource failed:",e),this.chatgpt_eventSource.close()}}catch(t){console.error("发送消息时出错：",t)}},closeEventSource(){this.loading=!1,this.eventSource&&this.eventSource.close()},scrollToBottom(){const e=this.$refs.messageContainer;e&&(e.scrollTop=e.scrollHeight)},beforeDestroy(){this.eventSource&&this.eventSource.close()},goToLogout(){Ae.push({name:"Logout"})},goToFeedback(){Ae.push({name:"Feedback"})}}},D=N,V=(0,l.A)(D,S,x,!1,null,"3e88b636",null),L=V.exports,Q=function(){var e=this,t=e._self._c;return t("div",{staticClass:"admin-dashboard-background"},[t("div",{staticClass:"top-bar"},[e._m(0),t("div",{staticClass:"right"},[t("button",{staticClass:"logout-button",on:{click:e.logout}},[e._v("登出")])])]),t("div",{staticClass:"dashboard-container"},[t("h2",[e._v("管理员仪表板")]),t("div",{staticClass:"function-buttons"},[t("button",{staticClass:"dashboard-button",on:{click:e.goToFeedback}},[e._v("查看反馈信息")]),t("button",{staticClass:"dashboard-button",on:{click:e.goToUserInformation}},[e._v("查看用户信息")])]),t("p",[e._v(e._s(e.logoutMessage))])])])},J=[function(){var e=this,t=e._self._c;return t("div",{staticClass:"left"},[t("span",[e._v("ChatWithAIs V1 | 一站式大语言模型访问平台")])])}],K={name:"AdminDashboard",data(){return{logoutMessage:""}},methods:{logout(){Ae.push({name:"Logout"})},goToFeedback(){Ae.push({name:"AdminFeedback"})},goToUserInformation(){Ae.push({name:"AdminUserInfo"})}}},H=K,P=(0,l.A)(H,Q,J,!1,null,"138019c7",null),j=P.exports,W=function(){var e=this,t=e._self._c;return t("div",{staticClass:"logout-container"},[t("h2",[e._v("Logging out...")]),t("p",[e._v(e._s(e.logoutMessage))])])},G=[],X={name:"LogoutComponent",data(){return{logoutMessage:""}},async created(){await this.logout()},methods:{async logout(){try{const e=await m.A.get("/api/logout",{withCredentials:!0});"success"===e.data.status?(this.logoutMessage=e.data.message,setTimeout((()=>{Ae.push({name:"HomeView"}),this.logoutMessage=""}),1500)):this.logoutMessage=e.data.message}catch(e){console.error("Logout request failed:",e),this.logoutMessage="登出失败，请检查您的网络连接或重试。"}}}},Y=X,q=(0,l.A)(Y,W,G,!1,null,"7500240c",null),Z=q.exports,z=function(){var e=this,t=e._self._c;return t("div",{staticClass:"feedback-background"},[t("div",{staticClass:"top-bar"},[e._m(0),t("div",{staticClass:"right"},[t("button",{staticClass:"home-link",on:{click:e.goBack}},[e._v("返回")])])]),t("div",{staticClass:"feedback-container"},[t("div",{staticClass:"feedback-form"},[t("h2",[e._v("用户反馈")]),t("form",{on:{submit:function(t){return t.preventDefault(),e.submitFeedback.apply(null,arguments)}}},[t("textarea",{directives:[{name:"model",rawName:"v-model",value:e.feedback,expression:"feedback"}],attrs:{placeholder:"请输入您的反馈...",required:""},domProps:{value:e.feedback},on:{input:function(t){t.target.composing||(e.feedback=t.target.value)}}}),t("button",{attrs:{type:"submit"}},[e._v("提交反馈")])]),t("p",[e._v(e._s(e.feedbackMessage))])])])])},$=[function(){var e=this,t=e._self._c;return t("div",{staticClass:"left"},[t("span",[e._v("ChatWithAIs V1 | 一站式大语言模型访问平台")])])}];m.A.defaults.withCredentials=!0;var ee={name:"Feedback",data(){return{feedback:"",feedbackMessage:""}},methods:{async submitFeedback(){try{await m.A.post("/api/user/feedback",{message:this.feedback},{withCredentials:!0}),this.feedbackMessage="反馈提交成功！感谢您的反馈。",this.feedback=""}catch(e){this.feedbackMessage="反馈提交失败，请稍后重试。",console.error("Feedback submission error:",e)}},goBack(){Ae.push({name:"UserDashboard"})}}},te=ee,se=(0,l.A)(te,z,$,!1,null,"7a997e72",null),ae=se.exports,ne=function(){var e=this,t=e._self._c;return t("div",[t("div",{staticClass:"top-bar"},[e._m(0),t("div",{staticClass:"right"},[t("button",{staticClass:"home-link",on:{click:e.goBack}},[e._v("返回")])])]),e._m(1),e.feedbacks.length>0?t("div",{staticClass:"feedback-container"},[t("ul",e._l(e.feedbacks,(function(s){return t("li",{key:s.id,staticClass:"feedback-item"},[t("p",[t("strong",[e._v("反馈编号：")]),e._v(" "+e._s(s.id))]),t("p",[t("strong",[e._v("用户编号：")]),e._v(" "+e._s(s.user_id))]),t("p",[t("strong",[e._v("用户名：")]),e._v(" "+e._s(s.username))]),t("p",[t("strong",[e._v("消息：")]),e._v(" "+e._s(s.message))]),t("p",[t("strong",[e._v("时间戳：")]),e._v(" "+e._s(new Date(s.timestamp).toLocaleString()))])])})),0)]):t("div",[t("p",[e._v("暂无反馈。")])])])},oe=[function(){var e=this,t=e._self._c;return t("div",{staticClass:"left"},[t("span",[e._v("ChatWithAIs V1 | 一站式大语言模型访问平台")])])},function(){var e=this,t=e._self._c;return t("div",{staticClass:"feedback-heading"},[t("h2",[e._v("用户反馈信息")])])}],re={name:"AdminFeedback",data(){return{feedbacks:[]}},async created(){await this.fetchFeedbacks()},methods:{async fetchFeedbacks(){try{const e=await m.A.get("/api/admin/feedback",{withCredentials:!0});this.feedbacks=e.data.feedbacks}catch(e){console.error("获取反馈信息时出错：",e)}},goBack(){Ae.push({name:"AdminDashboard"})}}},ie=re,ce=(0,l.A)(ie,ne,oe,!1,null,"d07862da",null),le=ce.exports,ue=function(){var e=this,t=e._self._c;return t("div",[t("div",{staticClass:"top-bar"},[e._m(0),t("div",{staticClass:"right"},[t("button",{staticClass:"home-link",on:{click:e.goBack}},[e._v("返回")])])]),e._m(1),e.users.length>0?t("div",{staticClass:"user-container"},[t("ul",e._l(e.users,(function(s){return t("li",{key:s.id,staticClass:"user-item"},[t("p",[t("strong",[e._v("用户编号：")]),e._v(" "+e._s(s.id))]),t("p",[t("strong",[e._v("用户名：")]),e._v(" "+e._s(s.username))]),t("p",[t("strong",[e._v("是否为管理员：")]),e._v(" "+e._s(s.is_admin?"是":"否"))])])})),0)]):t("div",[t("p",[e._v("暂无用户信息。")])])])},de=[function(){var e=this,t=e._self._c;return t("div",{staticClass:"left"},[t("span",[e._v("ChatWithAIs V1 | 一站式大语言模型访问平台")])])},function(){var e=this,t=e._self._c;return t("div",{staticClass:"info-heading"},[t("h2",[e._v("用户信息")])])}];m.A.defaults.withCredentials=!0;var ge={name:"UserInformation",data(){return{users:[]}},async created(){await this.fetchUsers()},methods:{async fetchUsers(){try{const e=await m.A.get("/api/admin/users",{withCredentials:!0});this.users=e.data.users}catch(e){console.error("获取用户信息失败：",e)}},goBack(){Ae.push({name:"AdminDashboard"})}}},he=ge,me=(0,l.A)(he,ue,de,!1,null,"86f0dbfe",null),pe=me.exports;a["default"].use(n.Ay);const ve=[{path:"/",name:"HomeView",component:d},{path:"/login",name:"Login",component:A},{path:"/register",name:"Register",component:y},{path:"/user-dashboard",name:"UserDashboard",component:L,meta:{requiresAuth:!0,role:"user"}},{path:"/admin-dashboard",name:"AdminDashboard",component:j,meta:{requiresAuth:!0,role:"admin"}},{path:"/logout",name:"Logout",component:Z},{path:"/feedback",name:"Feedback",component:ae},{path:"/admin-feedback",name:"AdminFeedback",component:le},{path:"/admin-userinfo",name:"AdminUserInfo",component:pe}],fe=new n.Ay({routes:ve});var Ae=fe,Ce=s(93518);a["default"].use(Ce.Ay);var be=new Ce.Ay.Store({state:{},getters:{},mutations:{},actions:{},modules:{}}),we=s(89143),ke=s.n(we),_e=function(){var e=this,t=e._self._c;return t("div",{attrs:{id:"app"}},[t("router-view")],1)},ye=[],Se={name:"App"},xe=Se,Ee=(0,l.A)(xe,_e,ye,!1,null,null,null),Be=Ee.exports;s(33597);a["default"].use(ke()),a["default"].config.productionTip=!1,a["default"].directive("highlight",(function(e){let t=e.querySelectorAll("pre code");t.forEach((e=>{R.A.highlightBlock(e)}))})),new a["default"]({router:Ae,store:be,render:e=>e(Be)}).$mount("#app")},61927:function(e){e.exports="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAeCAYAAAA7MK6iAAAACXBIWXMAAAsTAAALEwEAmpwYAAAC/0lEQVR4nO2WS0iVQRTHf5k9TCQ1CimKqDAkcFUUZoa9FrWQFiK1TAgi7AHh3UhQRFHRa5FlEGUPoU24KyqpXZRkL0OCCNIem1Zp3lLzi4H/xGH4vnt72M4/XLgzc2b+M+f8zzkfjCMZk4HtwGPgK9APdAFNQCH/CfOB10CU8PsIVI416SygTwRPgRpgOjANWAvc19oXvT4FbAWK/5X4gg6+C0wN1nKB3cBIjBeGgRNA3p+Q5QN7gQ7gB5AG5gQ264FuQ/QKOA7sB9pF7L1U+Duky4EPwe1vm/WFOtivvZH7Q5QZXbRlI10ixTrjh8AV/W/R+gzgs4mpi+eUDOctAgaAUaA0yWgC8ESHtgITgR0aN8tmtcY3gBKzd5m88hLYBuTEaKQxibhKBu+NIELiao2dLYp7q16UNu7vBCpkU6+5i0nEjTJwSiSBeI3GG5Q6AyI8DBQAW4Be2bjLXAcOaXwuifiIDHZlIF6ncb853Hmo1uxx+X0AGAwEujPbi4+aOe+m8yaFImmhStWqS3OukJSbvfMC9W9KIl5p0mOS5uYCn5STZ4A62fj4OazQ3JAKSbPU73HSxN2K7hdy1ACc0Skz7w45q0OHtO7IPCo0V6fLDeuy7tK+ubyVjXtcLDYa17TLXR7lpi47966Su30KujCgsEQKk8exbCnVEAhiUEJxgvGolaBGA6E54SFXRxKmxx7NOfXHokUGB5UK/vBepUqBNqeVSk1KrUiplkR8WnP7kogvycBVHx+/TuOBtJrGZWB2UHiqE4jz1K8zxjgV1GYvOneRF8AtYKlZK1H5jFROQ2JXdq8ZVbuyHItSude5cUGSkRpDSo0iUuMoDmrzVeCR0UEZWdAm4x5gccx6jXLdqt9e8k4g0D41kawoUvN2m74DNyUiJ6pn5sBuo2QPl7vflPP39HViMyIr8tQs/FeE/Y2onufG7OmI0chfoUhplNKrfUwf6LX5+qzZDDzX2jtgJmOMSpMacb+eoNqNKQr1+i6pdUCfSfWmuYyDED8BOKIZsmUtfr8AAAAASUVORK5CYII="},955:function(e,t,s){e.exports=s.p+"img/homepage1.a32af312.png"},3392:function(e,t,s){e.exports=s.p+"img/homepage2.dc8bd675.png"},27593:function(e,t,s){e.exports=s.p+"img/homepage3.faec6f38.png"},24490:function(e){e.exports="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAOlJREFUOE/dk70uRFEURtdSUWk8gIRGSTRCqNSi9AbTiFL0Gp1iCg+hoFaRCIVQakjmATQqhcTn3sklM9cdGbmd3Z2c71v755wtLcOWfn4FJNkB3tXTUYlGApJsABeVcVO9bII0ApIsALfAZGV6A1bUxzrkByDJDPAAPANPlWEemAMW1ZdByBAgyRRwBUwDy8BRJd4H7oBXYF0tK+rHNyDJRJHhvOh7FVhSe0lO+iLtJJkF7oHrosIt9aMO2Ab2gAP1prwcBFTnNeAQOFbPhgBNE64Dxn6FL+H/AOyWs1S7f/7K4y5Z6238BJJ5URH8OYOzAAAAAElFTkSuQmCC"},14487:function(e){e.exports="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAbJJREFUOE+l0z1IW1EYBuD3Ozc3iX94rwGVoiBJr44dunRwzaDYQTcHLUIheuLmohTchE7+0CZNcRDERdFNugguCs6CICTBgBQUW3Nto7YxueeTDFGj0Upz5vM+5/D9ECo8VGEejwMLKa/5J9cHJiPPVcuZ0ZbTco+VB76y3pBPrgO0oaB+CmD4r8vdexlqO7qPlAXMSEIq4ORX2FotBIzYwStSTsiWlnwW0BCJL+Q9VWO/37emiwEzGl+3ZXvPswAjmpgkFpt2OLBdCNR+STbqrOZs2d7/b2DxuMbMnE8yuJs1MQTlpAXTEoOP8kKMnI+8PLmLlNSg+tPhC6+WXVOgGEPfEnw1TgQDCjOssQ9MEyw0eTbs3y0it0Ch8k5iO6e0gcxoIF6uZXWfv/tc4nIzRyJY/MkNYEaTXQB32tL68NRwGdHkOwH2paU1Xbh3A9TH4kHh0Gs7bH18CjAjibdMCJxJa7YEwMqe2/zh2QHxPDTtmx0KHN6FauYPmvSs84YIU1mXHiwOVekgrey560+9nQLcAWY/MfxMcANIEVMKoP10Xe0WBpsvHhbxP7eq4m28BsikoBFyc4qBAAAAAElFTkSuQmCC"},74970:function(e){e.exports="data:image/png;base64,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"},89910:function(e){e.exports="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAIRJREFUOE/t0kEKwkAMheGvuPYSVReCekMV6wlF7Ma60Cu4VMEOzOhsRGi3zSoJyR/yeIWeUfTcNwB8NBhhiQvumbBTPHDNemNMcMQriVi1xRonLOLwCoeYz9DE/IwA3mCfALvYyAEBFK6EyAE15tiiSoBfL5R44vbvhc5+Goz0NVJnEd9zOBgR2GT1sQAAAABJRU5ErkJggg=="},15604:function(e){e.exports="data:image/png;base64,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"}},t={};function s(a){var n=t[a];if(void 0!==n)return n.exports;var o=t[a]={id:a,loaded:!1,exports:{}};return e[a].call(o.exports,o,o.exports,s),o.loaded=!0,o.exports}s.m=e,function(){s.amdO={}}(),function(){var e=[];s.O=function(t,a,n,o){if(!a){var r=1/0;for(u=0;u<e.length;u++){a=e[u][0],n=e[u][1],o=e[u][2];for(var i=!0,c=0;c<a.length;c++)(!1&o||r>=o)&&Object.keys(s.O).every((function(e){return s.O[e](a[c])}))?a.splice(c--,1):(i=!1,o<r&&(r=o));if(i){e.splice(u--,1);var l=n();void 0!==l&&(t=l)}}return t}o=o||0;for(var u=e.length;u>0&&e[u-1][2]>o;u--)e[u]=e[u-1];e[u]=[a,n,o]}}(),function(){s.n=function(e){var t=e&&e.__esModule?function(){return e["default"]}:function(){return e};return s.d(t,{a:t}),t}}(),function(){s.d=function(e,t){for(var a in t)s.o(t,a)&&!s.o(e,a)&&Object.defineProperty(e,a,{enumerable:!0,get:t[a]})}}(),function(){s.g=function(){if("object"===typeof globalThis)return globalThis;try{return this||new Function("return this")()}catch(e){if("object"===typeof window)return window}}()}(),function(){s.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)}}(),function(){s.r=function(e){"undefined"!==typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})}}(),function(){s.nmd=function(e){return e.paths=[],e.children||(e.children=[]),e}}(),function(){s.p="/"}(),function(){var e={524:0};s.O.j=function(t){return 0===e[t]};var t=function(t,a){var n,o,r=a[0],i=a[1],c=a[2],l=0;if(r.some((function(t){return 0!==e[t]}))){for(n in i)s.o(i,n)&&(s.m[n]=i[n]);if(c)var u=c(s)}for(t&&t(a);l<r.length;l++)o=r[l],s.o(e,o)&&e[o]&&e[o][0](),e[o]=0;return s.O(u)},a=self["webpackChunkchat_frontend"]=self["webpackChunkchat_frontend"]||[];a.forEach(t.bind(null,0)),a.push=t.bind(null,a.push.bind(a))}();var a=s.O(void 0,[504],(function(){return s(42662)}));a=s.O(a)})();
//# sourceMappingURL=app.5acb1487.js.map