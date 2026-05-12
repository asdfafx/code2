// IP 地理位置和行为时间线功能脚本

// 加载地理位置统计
async function loadGeoStats() {
    try {
        const response = await fetch(`${API_BASE}/geo/stats`);
        const data = await response.json();
        
        // 显示地理位置分布
        const locationDiv = document.getElementById('locationDistribution');
        if (locationDiv) {
            let html = '<table><thead><tr><th>国家/地区</th><th>请求数</th><th>独立IP</th><th>攻击数</th><th>攻击率</th></tr></thead><tbody>';
            
            for (const [country, stats] of Object.entries(data.location_distribution)) {
                html += `
                    <tr>
                        <td>${country}</td>
                        <td>${stats.count}</td>
                        <td>${stats.unique_ips}</td>
                        <td>${stats.attacks}</td>
                        <td>${stats.attack_rate}%</td>
                    </tr>
                `;
            }
            
            html += '</tbody></table>';
            locationDiv.innerHTML = html;
        }
        
        // 显示异常告警
        const anomaliesDiv = document.getElementById('anomaliesList');
        if (anomaliesDiv) {
            if (data.anomalies.length === 0) {
                anomaliesDiv.innerHTML = '<p style="color: #4caf50;">✅ 未检测到异常地区访问</p>';
            } else {
                let html = '<div style="margin-bottom: 15px;"><strong>⚠️ 检测到 ' + data.anomalies.length + ' 个异常地区：</strong></div>';
                
                data.anomalies.forEach(anomaly => {
                    const severityClass = anomaly.severity === 'high' ? 'risk-high' : 'risk-medium';
                    html += `
                        <div class="detail-section" style="margin-bottom: 10px;">
                            <div class="detail-row"><span class="detail-label">国家/地区：</span><span class="detail-value">${anomaly.country}</span></div>
                            <div class="detail-row"><span class="detail-label">攻击率：</span><span class="detail-value ${severityClass}">${anomaly.attack_rate}%</span></div>
                            <div class="detail-row"><span class="detail-label">总请求：</span><span class="detail-value">${anomaly.total_requests}</span></div>
                            <div class="detail-row"><span class="detail-label">攻击次数：</span><span class="detail-value">${anomaly.attacks}</span></div>
                            <div class="detail-row"><span class="detail-label">独立IP：</span><span class="detail-value">${anomaly.unique_ips}</span></div>
                        </div>
                    `;
                });
                
                anomaliesDiv.innerHTML = html;
            }
        }
        
    } catch (error) {
        console.error('加载地理位置统计失败:', error);
    }
}

// 加载地图数据
async function loadMapData() {
    try {
        const response = await fetch(`${API_BASE}/geo/map-data`);
        const data = await response.json();
        
        const mapContainer = document.getElementById('mapContainer');
        if (!mapContainer) return;
        
        if (data.map_points.length === 0) {
            mapContainer.innerHTML = '<p style="text-align: center; color: #666; padding: 40px;">暂无地图数据（需要包含经纬度的 IP 地址）</p>';
            return;
        }
        
        // 创建简单的地图可视化（使用散点图模拟）
        let html = '<div style="position: relative; height: 400px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 10px; overflow: hidden;">';
        html += '<div style="position: absolute; top: 10px; left: 10px; color: white; background: rgba(0,0,0,0.5); padding: 10px; border-radius: 5px;">';
        html += `<strong>攻击来源地图</strong><br>共 ${data.total_points} 个位置点`;
        html += '</div>';
        
        // 简化的世界地图表示（实际项目中应使用 Leaflet 或百度地图）
        data.map_points.forEach(point => {
            if (point.latitude && point.longitude) {
                // 转换为相对位置（简化版）
                const x = ((point.longitude + 180) / 360) * 100;
                const y = ((90 - point.latitude) / 180) * 100;
                
                const color = point.risk_level === '高风险' ? '#f44336' : point.risk_level === '中风险' ? '#ff9800' : '#4caf50';
                const size = Math.min(20, Math.max(5, point.requests / 2));
                
                html += `<div style="position: absolute; left: ${x}%; top: ${y}%; width: ${size}px; height: ${size}px; background: ${color}; border-radius: 50%; opacity: 0.7; cursor: pointer;" title="${point.ip}\\n${point.country} ${point.city}\\n请求: ${point.requests}, 攻击: ${point.attacks}" onclick="showIPDetail('${point.ip}')"></div>`;
            }
        });
        
        html += '</div>';
        
        // 添加图例
        html += '<div style="margin-top: 15px; display: flex; gap: 20px; justify-content: center;">';
        html += '<div><span style="display: inline-block; width: 12px; height: 12px; background: #f44336; border-radius: 50%; margin-right: 5px;"></span>高风险</div>';
        html += '<div><span style="display: inline-block; width: 12px; height: 12px; background: #ff9800; border-radius: 50%; margin-right: 5px;"></span>中风险</div>';
        html += '<div><span style="display: inline-block; width: 12px; height: 12px; background: #4caf50; border-radius: 50%; margin-right: 5px;"></span>低风险</div>';
        html += '</div>';
        
        mapContainer.innerHTML = html;
        
    } catch (error) {
        console.error('加载地图数据失败:', error);
    }
}

// 显示 IP 详情
async function showIPDetail(ip) {
    try {
        const response = await fetch(`${API_BASE}/geo/ip/${ip}`);
        const data = await response.json();
        
        if (response.ok) {
            const location = data.location;
            alert(`IP: ${location.ip}\n国家: ${location.country}\n地区: ${location.region}\n城市: ${location.city}\n类型: ${location.is_private ? '内网' : '公网'}`);
        }
    } catch (error) {
        console.error('查询 IP 详情失败:', error);
    }
}

// 加载行为时间线
async function loadTimeline() {
    try {
        // 获取顶级攻击者
        const attackersResponse = await fetch(`${API_BASE}/timeline/top-attackers?limit=10`);
        const attackersData = await attackersResponse.json();
        
        const attackersDiv = document.getElementById('topAttackers');
        if (attackersDiv) {
            if (attackersData.top_attackers.length === 0) {
                attackersDiv.innerHTML = '<p style="color: #666;">暂无攻击记录</p>';
            } else {
                let html = '<table><thead><tr><th>排名</th><th>IP 地址</th><th>攻击次数</th><th>平均风险分</th><th>操作</th></tr></thead><tbody>';
                
                attackersData.top_attackers.forEach((attacker, index) => {
                    html += `
                        <tr>
                            <td>${index + 1}</td>
                            <td>${attacker.ip}</td>
                            <td>${attacker.attack_count}</td>
                            <td>${attacker.avg_risk_score}</td>
                            <td><button class="btn btn-primary" onclick="viewIPTimeline('${attacker.ip}')">查看时间线</button></td>
                        </tr>
                    `;
                });
                
                html += '</tbody></table>';
                attackersDiv.innerHTML = html;
            }
        }
        
        // 获取行为模式
        const patternsResponse = await fetch(`${API_BASE}/timeline/patterns`);
        const patternsData = await patternsResponse.json();
        
        const patternsDiv = document.getElementById('behaviorPatterns');
        if (patternsDiv) {
            const summary = patternsData.summary;
            let html = '<div class="stats-grid">';
            html += `<div class="stat-card"><div class="stat-number">${summary.brute_force_count}</div><div class="stat-label">暴力破解</div></div>`;
            html += `<div class="stat-card"><div class="stat-number">${summary.scanning_count}</div><div class="stat-label">扫描行为</div></div>`;
            html += `<div class="stat-card"><div class="stat-number">${summary.distributed_count}</div><div class="stat-label">分布式攻击</div></div>`;
            html += `<div class="stat-card"><div class="stat-number">${summary.persistent_count}</div><div class="stat-label">持续攻击</div></div>`;
            html += '</div>';
            
            patternsDiv.innerHTML = html;
        }
        
        // 获取攻击链路
        const chainsResponse = await fetch(`${API_BASE}/timeline/chains`);
        const chainsData = await chainsResponse.json();
        
        const chainsDiv = document.getElementById('attackChains');
        if (chainsDiv) {
            if (chainsData.chains.length === 0) {
                chainsDiv.innerHTML = '<p style="color: #4caf50;">✅ 未检测到复杂攻击链路</p>';
            } else {
                let html = `<div style="margin-bottom: 15px;"><strong>🔗 检测到 ${chainsData.total_chains} 个攻击链路：</strong></div>`;
                
                chainsData.chains.forEach((chain, index) => {
                    html += `
                        <div class="detail-section" style="margin-bottom: 15px;">
                            <h4>链路 ${index + 1} - ${chain.chain_length} 个事件</h4>
                            <div class="detail-row"><span class="detail-label">严重程度：</span><span class="detail-value risk-${chain.severity}">${chain.severity}</span></div>
                            <div class="detail-row"><span class="detail-label">涉及 IP：</span><span class="detail-value">${chain.ip_count} 个</span></div>
                            <div class="detail-row"><span class="detail-label">攻击类型：</span><span class="detail-value">${chain.attack_types.join(', ') || '未知'}</span></div>
                            <div class="detail-row"><span class="detail-label">持续时间：</span><span class="detail-value">${chain.duration_seconds} 秒</span></div>
                            <div class="detail-row"><span class="detail-label">时间范围：</span><span class="detail-value">${new Date(chain.start_time).toLocaleString()} - ${new Date(chain.end_time).toLocaleString()}</span></div>
                        </div>
                    `;
                });
                
                chainsDiv.innerHTML = html;
            }
        }
        
    } catch (error) {
        console.error('加载时间线数据失败:', error);
    }
}

// 查看 IP 时间线
async function viewIPTimeline(ip) {
    try {
        const response = await fetch(`${API_BASE}/timeline/ip/${ip}`);
        const data = await response.json();
        
        if (!response.ok) {
            alert('加载时间线失败');
            return;
        }
        
        const timeline = data.timeline;
        const stats = timeline.statistics;
        
        let content = `
            <div class="detail-section">
                <h3>📍 IP 信息</h3>
                <div class="detail-row"><span class="detail-label">IP 地址：</span><span class="detail-value">${timeline.ip_address}</span></div>
                <div class="detail-row"><span class="detail-label">总请求：</span><span class="detail-value">${stats.total_requests}</span></div>
                <div class="detail-row"><span class="detail-label">攻击次数：</span><span class="detail-value">${stats.attack_count}</span></div>
                <div class="detail-row"><span class="detail-label">攻击率：</span><span class="detail-value">${stats.attack_rate}%</span></div>
                <div class="detail-row"><span class="detail-label">首次出现：</span><span class="detail-value">${stats.first_seen ? new Date(stats.first_seen).toLocaleString() : '未知'}</span></div>
                <div class="detail-row"><span class="detail-label">最后出现：</span><span class="detail-value">${stats.last_seen ? new Date(stats.last_seen).toLocaleString() : '未知'}</span></div>
                <div class="detail-row"><span class="detail-label">活动时长：</span><span class="detail-value">${stats.duration_seconds} 秒</span></div>
            </div>
            
            <div class="detail-section">
                <h3>⏱️ 行为时间线（最近 ${Math.min(timeline.timeline.length, 50)} 条）</h3>
                <table>
                    <thead>
                        <tr>
                            <th>时间</th>
                            <th>方法</th>
                            <th>URL</th>
                            <th>状态码</th>
                            <th>风险分</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        
        timeline.timeline.slice(0, 50).forEach(event => {
            const riskClass = event.is_attack ? 'risk-high' : '';
            content += `
                <tr>
                    <td>${event.timestamp ? new Date(event.timestamp).toLocaleString() : ''}</td>
                    <td>${event.method}</td>
                    <td>${event.url ? event.url.substring(0, 50) : ''}</td>
                    <td>${event.status_code}</td>
                    <td class="${riskClass}">${event.risk_score}</td>
                </tr>
            `;
        });
        
        content += '</tbody></table></div>';
        
        document.getElementById('detailContent').innerHTML = content;
        document.getElementById('detailModal').style.display = 'block';
        
    } catch (error) {
        console.error('加载 IP 时间线失败:', error);
        alert('加载时间线失败');
    }
}
